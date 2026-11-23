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

// DialFunc opens a connection to address and gives up at deadline. The
// deadline covers everything the dialer does, including the TLS handshake.
type DialFunc func(address, serverName string, deadline time.Time) (net.Conn, error)

type Pool struct {
	url            *url.URL
	password       string
	conns          chan *pooledConn
	logger         *log.Logger
	idleTimeout    time.Duration
	connectTimeout time.Duration
	dial           DialFunc
}

type pooledConn struct {
	conn     net.Conn
	lastUsed time.Time
}

// New creates a pool. connectTimeout bounds opening a connection (TCP dial,
// TLS handshake and AUTH) as a whole.
func New(redisURL string, poolSize int, idleTimeout, connectTimeout time.Duration, logger *log.Logger) (*Pool, error) {
	u, err := url.Parse(redisURL)
	if err != nil || (u.Scheme != "rediss") {
		return nil, fmt.Errorf("invalid Redis URL")
	}

	password, _ := u.User.Password()
	if password == "" {
		return nil, fmt.Errorf("empty Redis password")
	}

	return &Pool{
		url:            u,
		password:       password,
		conns:          make(chan *pooledConn, poolSize),
		logger:         logger,
		idleTimeout:    idleTimeout,
		connectTimeout: connectTimeout,
		dial:           tlsDial,
	}, nil
}

// SetDialer replaces the function used to open connections. It exists so
// tests can talk to a plain TCP server instead of a TLS one.
func (p *Pool) SetDialer(d DialFunc) {
	p.dial = d
}

// Idle returns the number of connections currently waiting in the pool.
func (p *Pool) Idle() int {
	return len(p.conns)
}

func tlsDial(address, serverName string, deadline time.Time) (net.Conn, error) {
	// The dialer's Deadline applies to the TCP connect and the TLS handshake as a whole.
	return tls.DialWithDialer(&net.Dialer{Deadline: deadline}, "tcp", address, &tls.Config{
		ServerName: serverName,
	})
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

// Put returns a healthy connection to the pool. Do not Put a connection that
// has returned an error or timed out: use Discard instead, because its
// protocol state is unknown and it may never answer again.
func (p *Pool) Put(conn net.Conn) {
	// Whoever Gets this connection next must not inherit an old deadline.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		p.logger.Printf("Clearing deadline failed, closing Redis connection: %v\n", err)
		p.closeConn(conn)
		return
	}
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

// Discard closes a connection that must not be reused.
func (p *Pool) Discard(conn net.Conn) {
	p.logger.Println("Discarding Redis connection")
	p.closeConn(conn)
}

func (p *Pool) connect() (net.Conn, error) {
	port := p.url.Port()
	if port == "" {
		port = "6379"
	}
	address := net.JoinHostPort(p.url.Hostname(), port)

	// One deadline for the whole connection setup: dial, TLS handshake and AUTH.
	deadline := time.Now().Add(p.connectTimeout)
	conn, err := p.dial(address, p.url.Hostname(), deadline)
	if err != nil {
		return nil, err
	}

	p.logger.Println("Connected to Redis over TLS")
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, fmt.Errorf("redis set deadline failed: %w", err)
	}

	// Redis RESP Protocol format https://redis-doc-test.readthedocs.io/en/latest/topics/protocol/
	authCmd := fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(p.password), p.password)
	if _, err := conn.Write([]byte(authCmd)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("redis AUTH send failed: %w", err)
	}

	authResp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("redis AUTH read failed: %w", err)
	}
	if !strings.HasPrefix(authResp, "+OK") {
		conn.Close()
		return nil, fmt.Errorf("redis AUTH failed: %s", strings.TrimSpace(authResp))
	}

	// Clear the setup deadline; callers set a fresh one before each command.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("redis clear deadline failed: %w", err)
	}

	p.logger.Printf("New Redis connection established.")

	return conn, nil
}

func (p *Pool) closeConn(conn net.Conn) {
	conn.Close()
	p.logger.Printf("Closed Redis connection.")
}
