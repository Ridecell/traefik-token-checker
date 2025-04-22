package traefik_token_checker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	redispool "github.com/Ridecell/traefik-token-checker/redis"
)

type Config struct {
	RedisURL          string `json:"redisURL,omitempty"`
	LogLevel          string `json:"logLevel,omitempty"`
	PoolSize          int    `json:"poolSize,omitempty"`
	IdleTimeInSeconds int    `json:"idleTime,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		LogLevel:          "ERROR",
		PoolSize:          50,
		IdleTimeInSeconds: 60,
	}
}

type JWT struct {
	next      http.Handler
	name      string
	config    *Config
	redisPool *redispool.Pool
}

var (
	LoggerDEBUG = log.New(io.Discard, "DEBUG: tokenChecker: ", log.Ldate|log.Ltime|log.Lshortfile)
	LoggerERROR = log.New(io.Discard, "ERROR: tokenChecker: ", log.Ldate|log.Ltime|log.Lshortfile)
)

func SetLogger(level string) {
	switch level {
	case "ERROR":
		LoggerERROR.SetOutput(os.Stdout)
	case "DEBUG":
		LoggerERROR.SetOutput(os.Stdout)
		LoggerDEBUG.SetOutput(os.Stdout)
	default:
		LoggerERROR.SetOutput(os.Stdout)
	}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.RedisURL == "" {
		return nil, fmt.Errorf("redisURL is required")
	}
	SetLogger(config.LogLevel)
	IdleTimeout := time.Duration(config.IdleTimeInSeconds) * time.Second
	pool, err := redispool.New(config.RedisURL, config.PoolSize, IdleTimeout, LoggerDEBUG)
	if err != nil {
		return nil, err
	}

	return &JWT{
		next:      next,
		name:      name,
		config:    config,
		redisPool: pool,
	}, nil
}

func (jwt *JWT) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	authToken := req.Header.Get("Authorization")
	devToken := req.Header.Get("Developer-token")

	if authToken != "" || devToken != "" {

		conn, err := jwt.redisPool.Get()
		if err != nil {
			LoggerERROR.Printf("Error getting Redis connection: %v", err)
			jwt.next.ServeHTTP(rw, req)
			return
		}
		defer jwt.redisPool.Put(conn)
		isAuthBlacklisted := false
		isDevBlacklisted := false

		isAuthBlacklisted, err = jwt.checkToken(conn, authToken)
		if err != nil {
			LoggerERROR.Printf("Error checking auth token: %v", err)
		}

		isDevBlacklisted, err = jwt.checkToken(conn, devToken)
		if err != nil {
			LoggerERROR.Printf("Error checking dev token: %v", err)
		}

		if isAuthBlacklisted || isDevBlacklisted {
			LoggerDEBUG.Println("Blacklisted token detected, blocking request")
			rw.Header().Set("Content-Type", "application/json")
			if req.Header.Get("origin") != "" {
				rw.Header().Set("Access-Control-Allow-Origin", req.Header.Get("origin"))
			}
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte(`{"error_msg":"expired_jwt_token"}`))
			return
		}
	}
	LoggerDEBUG.Println("Blacklisted token not found, forwarding request")
	jwt.next.ServeHTTP(rw, req)
}

func (jwt *JWT) checkToken(conn net.Conn, rawToken string) (bool, error) {
	if !strings.HasPrefix(rawToken, "JWT ") {
		return false, nil
	}

	token := strings.TrimPrefix(rawToken, "JWT ")

	cmd := fmt.Sprintf("*2\r\n$6\r\nEXISTS\r\n$%d\r\n%s\r\n", len(token), token)
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return false, fmt.Errorf("redis EXISTS send failed")
	}

	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("redis EXISTS response read failed")
	}

	reply = strings.TrimSpace(reply)

	switch reply {
	case ":1":
		return true, nil
	case ":0":
		return false, nil
	default:
		return false, fmt.Errorf("unexpected Redis response: %s", reply)
	}
}
