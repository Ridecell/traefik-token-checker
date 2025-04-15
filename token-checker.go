package traefik_token_checker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	RedisURL string `json:"redisURL,omitempty"`
	LogLevel string `json:"logLevel,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		LogLevel: "ERROR",
	}
}

type JWT struct {
	next   http.Handler
	name   string
	config *Config
}

var (
	LoggerDEBUG = log.New(io.Discard, "DEBUG: tokenChecker: ", log.Ldate|log.Ltime|log.Lshortfile)
	LoggerERROR = log.New(io.Discard, "ERROR: tokenChecker: ", log.Ldate|log.Ltime|log.Lshortfile)
)

func SetLogger(level string) {
	switch level {
	case "ERROR":
		LoggerERROR.SetOutput(os.Stderr)
	case "DEBUG":
		LoggerERROR.SetOutput(os.Stderr)
		LoggerDEBUG.SetOutput(os.Stdout)
	default:
		LoggerERROR.SetOutput(os.Stderr)
	}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.RedisURL == "" {
		return nil, fmt.Errorf("redisURL is required")
	}
	SetLogger(config.LogLevel)
	return &JWT{
		next:   next,
		name:   name,
		config: config,
	}, nil
}

func (jwt *JWT) getRedisConnection() (net.Conn, error) {
	u, err := url.Parse(jwt.config.RedisURL)
	if err != nil || u.Scheme != "redis" {
		return nil, fmt.Errorf("redis URL parse error")
	}

	port := u.Port()
	if port == "" {
		port = "6379"
	}

	address := net.JoinHostPort(u.Hostname(), port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("could not connect to Redis")
	}

	password, _ := u.User.Password()
	if password == "" {
		return nil, fmt.Errorf("empty Redis password")
	}

	authCmd := fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(password), password)
	if _, err := conn.Write([]byte(authCmd)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("redis AUTH send failed")
	}

	authResp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.HasPrefix(authResp, "+OK") {
		conn.Close()
		return nil, fmt.Errorf("redis AUTH failed")
	}

	return conn, nil
}

func (jwt *JWT) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	authToken := req.Header.Get("Authorization")
	devToken := req.Header.Get("Developer-token")

	if authToken != "" || devToken != "" {

		conn, err := jwt.getRedisConnection()
		if err != nil {
			LoggerERROR.Printf("Error getting Redis connection: %v", err)
			jwt.next.ServeHTTP(rw, req)
			return
		}
		defer conn.Close()
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
			rw.Write([]byte(`{"error_msg":"blacklisted_token"}`))
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
