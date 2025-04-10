// Package traefik_token_checker is a Traefik middleware plugin that checks token headers against Redis.
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
)

type Config struct {
	RedisHost string `json:"redisHost,omitempty"`
	RedisPort string `json:"redisPort,omitempty"`
	LogLevel  string `json:"logLevel,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		LogLevel: "INFO",
	}
}

type JWT struct {
	next   http.Handler
	name   string
	config *Config
}

var (
	LoggerDEBUG   = log.New(io.Discard, "DEBUG: tokenChecker: ", log.Ldate|log.Ltime|log.Lshortfile)
	LoggerINFO    = log.New(io.Discard, "INFO: tokenChecker: ", log.Ldate|log.Ltime|log.Lshortfile)
	LoggerWARNING = log.New(io.Discard, "WARNING: tokenChecker: ", log.Ldate|log.Ltime|log.Lshortfile)
	LoggerERROR   = log.New(io.Discard, "ERROR: tokenChecker: ", log.Ldate|log.Ltime|log.Lshortfile)
)

func SetLogger(level string) {
	switch level {
	case "ERROR":
		LoggerERROR.SetOutput(os.Stderr)
	case "WARNING":
		LoggerERROR.SetOutput(os.Stderr)
		LoggerWARNING.SetOutput(os.Stderr)
	case "INFO":
		LoggerERROR.SetOutput(os.Stderr)
		LoggerWARNING.SetOutput(os.Stderr)
		LoggerINFO.SetOutput(os.Stdout)
	case "DEBUG":
		LoggerERROR.SetOutput(os.Stderr)
		LoggerWARNING.SetOutput(os.Stderr)
		LoggerINFO.SetOutput(os.Stdout)
		LoggerDEBUG.SetOutput(os.Stdout)
	default:
		LoggerERROR.SetOutput(os.Stderr)
		LoggerWARNING.SetOutput(os.Stderr)
		LoggerINFO.SetOutput(os.Stdout)
	}
}

// New creates a new middleware instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.RedisHost == "" || config.RedisPort == "" {
		return nil, fmt.Errorf("RedisHost is required")
	}
	SetLogger(config.LogLevel)
	return &JWT{
		next:   next,
		name:   name,
		config: config,
	}, nil
}

func (jwt *JWT) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	authToken := req.Header.Get("Authorization")
	devToken := req.Header.Get("Developer-token")

	LoggerDEBUG.Println("Authorization Token:", authToken)
	LoggerDEBUG.Println("Developer Token:", devToken)

	isAuthBlacklisted, err := jwt.isTokenBlacklisted(authToken)
	if err != nil {
		LoggerERROR.Printf("Error checking auth token in Redis: %v", err)
		http.Error(rw, "Internal error", http.StatusInternalServerError)
		return
	}

	isDevBlacklisted, err := jwt.isTokenBlacklisted(devToken)
	if err != nil {
		LoggerERROR.Printf("Error checking dev token in Redis: %v", err)
		http.Error(rw, "Internal error", http.StatusInternalServerError)
		return
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
	LoggerDEBUG.Println("Blacklisted token not found, forwarding request")
	jwt.next.ServeHTTP(rw, req)
}

func (jwt *JWT) isTokenBlacklisted(token string) (bool, error) {
	if token == "" || !(strings.Contains(token, "JWT ")) {
		return false, nil
	}

	token = strings.TrimPrefix(token, "JWT ")
	LoggerDEBUG.Printf("Checking Redis for token: %s", token)

	address := net.JoinHostPort(jwt.config.RedisHost, jwt.config.RedisPort)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return false, fmt.Errorf("failed to connect to Redis: %w", err)
	}
	defer conn.Close()

	// using RESP protocol for redis. DOC: https://redis-doc-test.readthedocs.io/en/latest/topics/protocol/
	cmd := fmt.Sprintf("*2\r\n$6\r\nEXISTS\r\n$%d\r\n%s\r\n", len(token), token)
	_, err = conn.Write([]byte(cmd))
	if err != nil {
		return false, fmt.Errorf("failed to write to Redis: %w", err)
	}

	reader := bufio.NewReader(conn)
	reply, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read from Redis: %w", err)
	}

	reply = strings.TrimSpace(reply)
	LoggerDEBUG.Printf("Redis response: %s", reply)
	switch reply {
	case ":1":
		return true, nil
	case ":0":
		return false, nil
	default:
		return false, fmt.Errorf("unexpected Redis response: %s", reply)
	}
}
