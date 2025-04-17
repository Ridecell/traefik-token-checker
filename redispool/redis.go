package redispool

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
	url      *url.URL
	password string
	conns    chan net.Conn
	logger   *log.Logger
}

func New(redisURL string, poolSize int, logger *log.Logger) (*Pool, error) {
	u, err := url.Parse(redisURL)
	if err != nil || (u.Scheme != "rediss" && u.Scheme != "redis") {
		return nil, fmt.Errorf("invalid Redis URL")
	}

	password, _ := u.User.Password()
	if password == "" {
		return nil, fmt.Errorf("empty Redis password")
	}

	return &Pool{
		url:      u,
		password: password,
		conns:    make(chan net.Conn, poolSize),
		logger:   logger,
	}, nil
}

func (p *Pool) Get() (net.Conn, error) {
	select {
	case conn := <-p.conns:
		p.logger.Println("Reusing Redis connection from pool")
		return conn, nil
	default:
		p.logger.Println("Creating new Redis connection")
		return p.connect()
	}
}

func (p *Pool) Put(conn net.Conn) {
	select {
	case p.conns <- conn:
		p.logger.Println("Returning Redis connection to pool")
	default:
		p.logger.Println("Pool full, closing Redis connection")
		conn.Close()
	}
}

func (p *Pool) connect() (net.Conn, error) {
	port := p.url.Port()
	if port == "" {
		port = "6379"
	}
	address := net.JoinHostPort(p.url.Hostname(), port)

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, &tls.Config{
		ServerName:         p.url.Hostname(),
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}

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

	return conn, nil
}
