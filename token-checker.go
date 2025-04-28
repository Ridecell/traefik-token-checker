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

	redispool "github.com/Ridecell/traefik-token-checker/internal/pkg/redis"
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

		// If Either of the token is not valid, then block the request
		if !(jwt.isTokenValid(conn, authToken) && jwt.isTokenValid(conn, devToken)) {
			LoggerDEBUG.Println("Blacklisted token detected, blocking request")
			rw.Header().Set("Content-Type", "application/json")
			if req.Header.Get("origin") != "" {
				// To avoid CORS error on browser level (Refer issue CAR-27637), we pass Access-Control-Allow-Origin header with Origin domain.
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

func (jwt *JWT) isTokenValid(conn net.Conn, rawToken string) bool {
	if !strings.HasPrefix(rawToken, "JWT ") {
		return false
	}

	token := strings.TrimPrefix(rawToken, "JWT ")

	cmd := fmt.Sprintf("*2\r\n$6\r\nEXISTS\r\n$%d\r\n%s\r\n", len(token), token)
	if _, err := conn.Write([]byte(cmd)); err != nil {
		LoggerERROR.Println("redis EXISTS send failed")
		return false
	}

	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		LoggerERROR.Println("redis EXISTS response read failed")
		return false
	}

	reply = strings.TrimSpace(reply)

	switch reply {
	case ":1":
		// This means token found in redis cache which is Blacklisted.
		return false
	case ":0":
		// This means token not found in redis cache. It is not Blacklisted.
		return true
	default:
		LoggerERROR.Printf("unexpected Redis response: %s", reply)
		return true
	}
}
