package redis

import (
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/Ridecell/traefik-token-checker/internal/pkg/redistest"
)

func newTestPool(t *testing.T, srv *redistest.Server, connectTimeout time.Duration) *Pool {
	t.Helper()
	p, err := New("rediss://:pw@"+srv.Addr(), 2, time.Minute, connectTimeout, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	p.SetDialer(func(address, serverName string, deadline time.Time) (net.Conn, error) {
		return (&net.Dialer{Deadline: deadline}).Dial("tcp", address)
	})
	return p
}

func TestConnectSucceedsAndClearsDeadline(t *testing.T) {
	srv := redistest.Start(t)
	p := newTestPool(t, srv, 200*time.Millisecond)

	conn, err := p.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer conn.Close()

	// The setup deadline must not leak into later commands: wait past it and
	// make sure the connection is still usable.
	time.Sleep(300 * time.Millisecond)
	if _, err := conn.Write([]byte("*2\r\n$6\r\nEXISTS\r\n$1\r\nx\r\n")); err != nil {
		t.Fatalf("write after connect deadline: %v", err)
	}
}

func TestConnectGivesUpWhenAuthNeverAnswers(t *testing.T) {
	srv := redistest.Start(t)
	srv.SetHangAuth(true)
	p := newTestPool(t, srv, 200*time.Millisecond)

	start := time.Now()
	conn, err := p.Get()
	elapsed := time.Since(start)
	if err == nil {
		conn.Close()
		t.Fatal("expected an error when AUTH is never answered")
	}
	if elapsed > time.Second {
		t.Fatalf("connect took %v, want it bounded near 200ms", elapsed)
	}
}

func TestDiscardClosesConnectionAndDoesNotPoolIt(t *testing.T) {
	srv := redistest.Start(t)
	p := newTestPool(t, srv, time.Second)

	conn, err := p.Get()
	if err != nil {
		t.Fatal(err)
	}
	p.Discard(conn)
	if p.Idle() != 0 {
		t.Fatalf("Idle = %d after Discard, want 0", p.Idle())
	}
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("expected write on a discarded connection to fail")
	}
}

func TestPutThenGetReusesConnection(t *testing.T) {
	srv := redistest.Start(t)
	p := newTestPool(t, srv, time.Second)

	conn, err := p.Get()
	if err != nil {
		t.Fatal(err)
	}
	p.Put(conn)
	if p.Idle() != 1 {
		t.Fatalf("Idle = %d after Put, want 1", p.Idle())
	}
	again, err := p.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if srv.Accepts() != 1 {
		t.Fatalf("server accepted %d connections, want 1 (reuse)", srv.Accepts())
	}
}

func TestPutClearsLeftoverDeadline(t *testing.T) {
	srv := redistest.Start(t)
	p := newTestPool(t, srv, time.Second)

	conn, err := p.Get()
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(-time.Second)) // a deadline that has already passed
	p.Put(conn)

	again, err := p.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if _, err := again.Write([]byte("*2\r\n$6\r\nEXISTS\r\n$1\r\nx\r\n")); err != nil {
		t.Fatalf("a pooled connection kept the previous deadline: %v", err)
	}
	if srv.Accepts() != 1 {
		t.Fatalf("server accepted %d connections, want 1 (reuse)", srv.Accepts())
	}
}
