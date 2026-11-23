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
	// RedisTimeoutMs bounds the whole Redis lookup of one request, covering the
	// EXISTS command for each token. On expiry the request is let through and
	// the connection is discarded.
	RedisTimeoutMs int `json:"redisTimeoutMs,omitempty"`
	// RedisConnectTimeoutMs bounds opening a Redis connection: TCP dial, TLS
	// handshake and AUTH together.
	RedisConnectTimeoutMs int `json:"redisConnectTimeoutMs,omitempty"`
	// SlowLogMs logs a line whenever the whole Redis step of a request takes at
	// least this long.
	SlowLogMs int `json:"slowLogMs,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		LogLevel:              "ERROR",
		PoolSize:              50,
		IdleTimeInSeconds:     60,
		RedisTimeoutMs:        250,
		RedisConnectTimeoutMs: 1000,
		SlowLogMs:             100,
	}
}

type JWT struct {
	next          http.Handler
	name          string
	config        *Config
	redisPool     *redispool.Pool
	redisTimeout  time.Duration
	slowThreshold time.Duration
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

// millis converts a configured number of milliseconds to a duration, falling
// back to def when the value is not positive.
func millis(v int, def int) time.Duration {
	if v <= 0 {
		v = def
	}
	return time.Duration(v) * time.Millisecond
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.RedisURL == "" {
		return nil, fmt.Errorf("redisURL is required")
	}
	SetLogger(config.LogLevel)
	IdleTimeout := time.Duration(config.IdleTimeInSeconds) * time.Second
	pool, err := redispool.New(config.RedisURL, config.PoolSize, IdleTimeout, millis(config.RedisConnectTimeoutMs, 1000), LoggerDEBUG)
	if err != nil {
		return nil, err
	}

	return &JWT{
		next:          next,
		name:          name,
		config:        config,
		redisPool:     pool,
		redisTimeout:  millis(config.RedisTimeoutMs, 250),
		slowThreshold: millis(config.SlowLogMs, 100),
	}, nil
}

func hasJWTPrefix(v string) bool {
	return strings.HasPrefix(v, "JWT ")
}

func (jwt *JWT) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	authToken := req.Header.Get("Authorization")
	devToken := req.Header.Get("Developer-token")

	// Only "JWT ..." values are looked up in Redis. Any other value is let
	// through without touching Redis, so it must not take a connection either.
	if hasJWTPrefix(authToken) || hasJWTPrefix(devToken) {
		start := time.Now()
		conn, err := jwt.redisPool.Get()
		getConn := time.Since(start)
		if err != nil {
			LoggerERROR.Printf("Error getting Redis connection: %v", err)
			jwt.logIfSlow(start, getConn, authToken, devToken, "get_conn_error")
			jwt.next.ServeHTTP(rw, req)
			return
		}

		// If Either of the token is not valid, then block the request
		valid, connErr := jwt.checkTokens(conn, authToken, devToken)
		if connErr != nil {
			// The connection timed out or broke. Its state is unknown, so never reuse it.
			jwt.redisPool.Discard(conn)
		} else {
			jwt.redisPool.Put(conn)
		}

		outcome := "ok"
		switch {
		case connErr != nil:
			outcome = "io_error"
		case !valid:
			outcome = "blacklisted"
		}
		jwt.logIfSlow(start, getConn, authToken, devToken, outcome)

		if !valid {
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

// logIfSlow reports a slow Redis step. It records only durations and whether
// each header was present, never the header values.
func (jwt *JWT) logIfSlow(start time.Time, getConn time.Duration, authToken, devToken, outcome string) {
	total := time.Since(start)
	if total < jwt.slowThreshold {
		return
	}
	LoggerERROR.Printf("slow redis step: total=%s get_conn=%s authorization=%t developer_token=%t outcome=%s",
		total, getConn, authToken != "", devToken != "", outcome)
}

// checkTokens reports whether the request may proceed. A non-nil error means
// the connection can no longer be trusted; the request is then let through
// (fail open), exactly as before.
func (jwt *JWT) checkTokens(conn net.Conn, authToken, devToken string) (bool, error) {
	// One deadline for the whole lookup, however many tokens it covers.
	deadline := time.Now().Add(jwt.redisTimeout)

	valid, err := jwt.isTokenValid(conn, authToken, deadline)
	if err != nil {
		return true, err
	}
	if valid {
		valid, err = jwt.isTokenValid(conn, devToken, deadline)
		if err != nil {
			return true, err
		}
	}

	return valid, nil
}

func (jwt *JWT) isTokenValid(conn net.Conn, rawToken string, deadline time.Time) (bool, error) {
	if !hasJWTPrefix(rawToken) {
		return true, nil
	}

	token := strings.TrimPrefix(rawToken, "JWT ")

	// Without a deadline a connection that stops answering blocks this request
	// until the operating system gives up.
	if err := conn.SetDeadline(deadline); err != nil {
		LoggerERROR.Printf("redis set deadline failed: %v", err)
		return true, err
	}

	cmd := fmt.Sprintf("*2\r\n$6\r\nEXISTS\r\n$%d\r\n%s\r\n", len(token), token)
	if _, err := conn.Write([]byte(cmd)); err != nil {
		LoggerERROR.Printf("redis EXISTS send failed: %v", err)
		return true, err
	}

	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		LoggerERROR.Printf("redis EXISTS response read failed: %v", err)
		return true, err
	}

	reply = strings.TrimSpace(reply)

	switch reply {
	case ":1":
		// This means token found in redis cache which is Blacklisted.
		return false, nil
	case ":0":
		// This means token not found in redis cache. It is not Blacklisted.
		return true, nil
	default:
		LoggerERROR.Printf("unexpected Redis response: %s", reply)
		return true, fmt.Errorf("unexpected Redis response")
	}
}
