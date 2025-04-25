package redis

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"time"
)

type Pool struct {
	url         *url.URL
	password    string
	conns       chan *pooledConn
	logger      *log.Logger
	idleTimeout time.Duration
}

type pooledConn struct {
	conn     net.Conn
	lastUsed time.Time
}

func New(redisURL string, poolSize int, idleTimeout time.Duration, logger *log.Logger) (*Pool, error) {
	u, err := url.Parse(redisURL)
	if err != nil || (u.Scheme != "rediss") {
		return nil, fmt.Errorf("invalid Redis URL")
	}

	password, _ := u.User.Password()
	if password == "" {
		return nil, fmt.Errorf("empty Redis password")
	}

	return &Pool{
		url:         u,
		password:    password,
		conns:       make(chan *pooledConn, poolSize),
		logger:      logger,
		idleTimeout: idleTimeout,
	}, nil
}

func (p *Pool) Get() (net.Conn, error) {
	select {
	case pc := <-p.conns:
		if time.Since(pc.lastUsed) > p.idleTimeout {
			p.logger.Printf("Idle timeout exceeded for connection last used at %v, closing it\n", (time.Since(pc.lastUsed) - p.idleTimeout).String())
			p.closeConn(pc.conn)
			return p.connect()
		}
		p.logger.Printf("Reusing Redis connection from pool (last used at %v ago)\n", (time.Since(pc.lastUsed) - p.idleTimeout).String())
		return pc.conn, nil
	default:
		p.logger.Println("Creating new Redis connection")
		return p.connect()
	}
}

func (p *Pool) Put(conn net.Conn) {
	pc := &pooledConn{conn: conn, lastUsed: time.Now()}
	p.logger.Printf("Returning Redis connection to pool (last used at %v)\n", pc.lastUsed)
	select {
	case p.conns <- pc:
		p.logger.Println("Connection returned to pool")
	default:
		p.logger.Println("Pool full, closing Redis connection")
		p.closeConn(conn)
	}
}

func (p *Pool) connect() (net.Conn, error) {
	port := p.url.Port()
	if port == "" {
		port = "6379"
	}
	address := net.JoinHostPort(p.url.Hostname(), port)

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, &tls.Config{
		ServerName: p.url.Hostname(),
	})
	if err != nil {
		return nil, err
	}

	p.logger.Println("Connected to Redis over TLS")
	// Redis RESP Protocol format https://redis-doc-test.readthedocs.io/en/latest/topics/protocol/
	authCmd := fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(p.password), p.password)
	if _, err := conn.Write([]byte(authCmd)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("redis AUTH send failed: %w", err)
	}

	authResp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.HasPrefix(authResp, "+OK") {
		conn.Close()
		return nil, fmt.Errorf("redis AUTH failed: %s", authResp)
	}

	p.logger.Printf("New Redis connection established.")

	return conn, nil
}

func (p *Pool) closeConn(conn net.Conn) {
	conn.Close()
	p.logger.Printf("Closed Redis connection.")
}
