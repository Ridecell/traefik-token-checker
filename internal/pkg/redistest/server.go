// Package redistest is a tiny fake Redis server for tests. It understands just
// enough RESP to answer AUTH and EXISTS, and can be told to misbehave.
package redistest

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Mode says how the server answers EXISTS.
type Mode int

const (
	NotBlacklisted Mode = iota // reply ":0"
	Blacklisted                // reply ":1"
	Hang                       // read the command, never reply
	Unexpected                 // reply with an error line
)

type Server struct {
	ln   net.Listener
	done chan struct{}
	wg   sync.WaitGroup

	mu        sync.Mutex
	mode      Mode
	delay     time.Duration
	hangAuth  bool
	accepts   int
	existsCmd int
}

// Start listens on a random local port and serves until the test ends.
func Start(t testing.TB) *Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &Server{ln: ln, done: make(chan struct{})}
	s.wg.Add(1)
	go s.acceptLoop()
	t.Cleanup(s.Close)
	return s
}

func (s *Server) Addr() string { return s.ln.Addr().String() }

// SetExists sets the reply mode and an optional delay before replying.
func (s *Server) SetExists(m Mode, delay time.Duration) {
	s.mu.Lock()
	s.mode, s.delay = m, delay
	s.mu.Unlock()
}

// SetHangAuth makes the server read AUTH and never answer it.
func (s *Server) SetHangAuth(v bool) {
	s.mu.Lock()
	s.hangAuth = v
	s.mu.Unlock()
}

// Accepts is the number of connections accepted so far.
func (s *Server) Accepts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepts
}

// ExistsCommands is the number of EXISTS commands received so far.
func (s *Server) ExistsCommands() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.existsCmd
}

func (s *Server) Close() {
	select {
	case <-s.done:
		return
	default:
		close(s.done)
	}
	s.ln.Close()
	s.wg.Wait()
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.accepts++
		s.mu.Unlock()
		s.wg.Add(1)
		go s.serve(c)
	}
}

func (s *Server) serve(c net.Conn) {
	defer s.wg.Done()
	defer c.Close()
	go func() { // unblock reads and hangs when the server closes
		<-s.done
		c.Close()
	}()
	r := bufio.NewReader(c)
	for {
		args, err := readCommand(r)
		if err != nil {
			return
		}
		switch strings.ToUpper(args[0]) {
		case "AUTH":
			s.mu.Lock()
			hang := s.hangAuth
			s.mu.Unlock()
			if hang {
				<-s.done
				return
			}
			c.Write([]byte("+OK\r\n"))
		case "EXISTS":
			s.mu.Lock()
			s.existsCmd++
			mode, delay := s.mode, s.delay
			s.mu.Unlock()
			if mode == Hang {
				<-s.done
				return
			}
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-s.done:
					return
				}
			}
			switch mode {
			case Blacklisted:
				c.Write([]byte(":1\r\n"))
			case Unexpected:
				c.Write([]byte("-ERR boom\r\n"))
			default:
				c.Write([]byte(":0\r\n"))
			}
		default:
			c.Write([]byte("-ERR unknown command\r\n"))
		}
	}
}

// readCommand reads one RESP array of bulk strings.
func readCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "*")))
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		l, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(hdr, "$")))
		if err != nil {
			return nil, err
		}
		buf := make([]byte, l+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:l]))
	}
	return args, nil
}
