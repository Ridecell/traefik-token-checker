package traefik_token_checker

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ridecell/traefik-token-checker/internal/pkg/redistest"
)

type fixture struct {
	handler  *JWT
	srv      *redistest.Server
	dials    *int32
	forwards *int32
}

func newFixture(t *testing.T, mutate func(*Config)) *fixture {
	t.Helper()
	srv := redistest.Start(t)
	cfg := CreateConfig()
	cfg.RedisURL = "rediss://:pw@" + srv.Addr()
	cfg.RedisTimeoutMs = 150
	cfg.RedisConnectTimeoutMs = 300
	cfg.SlowLogMs = 50
	if mutate != nil {
		mutate(cfg)
	}

	var forwards int32
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&forwards, 1)
		w.WriteHeader(http.StatusOK)
	})
	h, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	jwt := h.(*JWT)

	var dials int32
	jwt.redisPool.SetDialer(func(address, serverName string, deadline time.Time) (net.Conn, error) {
		atomic.AddInt32(&dials, 1)
		return (&net.Dialer{Deadline: deadline}).Dial("tcp", address)
	})
	return &fixture{handler: jwt, srv: srv, dials: &dials, forwards: &forwards}
}

func (f *fixture) do(headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func TestBlacklistedTokenIsRejected(t *testing.T) {
	f := newFixture(t, nil)
	f.srv.SetExists(redistest.Blacklisted, 0)

	rec := f.do(map[string]string{"Authorization": "JWT abc"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "expired_jwt_token") {
		t.Fatalf("unexpected body %q", rec.Body.String())
	}
	if atomic.LoadInt32(f.forwards) != 0 {
		t.Fatal("blacklisted request must not be forwarded")
	}
}

func TestCleanTokenIsForwardedAndConnectionReused(t *testing.T) {
	f := newFixture(t, nil)

	for i := 0; i < 3; i++ {
		if rec := f.do(map[string]string{"Authorization": "JWT abc"}); rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	}
	if got := atomic.LoadInt32(f.dials); got != 1 {
		t.Fatalf("dialed %d times, want 1 (the pooled connection is reused)", got)
	}
	if f.handler.redisPool.Idle() != 1 {
		t.Fatalf("Idle = %d, want the healthy connection back in the pool", f.handler.redisPool.Idle())
	}
}

func TestDeveloperTokenBlacklistedToo(t *testing.T) {
	f := newFixture(t, nil)
	f.srv.SetExists(redistest.Blacklisted, 0)

	rec := f.do(map[string]string{"Developer-token": "JWT dev"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestNonJWTHeadersNeverTouchRedis(t *testing.T) {
	f := newFixture(t, nil)

	for _, h := range []map[string]string{
		nil,
		{"Authorization": "Basic abc"},
		{"Authorization": "Bearer abc"},
		{"Developer-token": "plain-token"},
	} {
		if rec := f.do(h); rec.Code != http.StatusOK {
			t.Fatalf("headers %v: status = %d, want 200", h, rec.Code)
		}
	}
	if got := atomic.LoadInt32(f.dials); got != 0 {
		t.Fatalf("dialed %d times, want 0", got)
	}
}

func TestHungRedisFailsOpenWithinDeadlineAndDiscardsConnection(t *testing.T) {
	f := newFixture(t, nil)
	f.srv.SetExists(redistest.Hang, 0)

	start := time.Now()
	rec := f.do(map[string]string{"Authorization": "JWT abc"})
	elapsed := time.Since(start)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want the request let through", rec.Code)
	}
	if elapsed > time.Second {
		t.Fatalf("request took %v, want it bounded near the 150ms command deadline", elapsed)
	}
	if f.handler.redisPool.Idle() != 0 {
		t.Fatal("a connection that timed out must not go back into the pool")
	}
}

func TestHungRedisDoesNotPoisonNextRequest(t *testing.T) {
	f := newFixture(t, nil)
	f.srv.SetExists(redistest.Hang, 0)
	f.do(map[string]string{"Authorization": "JWT abc"})

	f.srv.SetExists(redistest.Blacklisted, 0)
	rec := f.do(map[string]string{"Authorization": "JWT abc"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 on a fresh connection", rec.Code)
	}
	if got := atomic.LoadInt32(f.dials); got != 2 {
		t.Fatalf("dialed %d times, want 2 (the stuck connection was dropped)", got)
	}
}

func TestHungAuthFailsOpenWithinConnectDeadline(t *testing.T) {
	f := newFixture(t, nil)
	f.srv.SetHangAuth(true)

	start := time.Now()
	rec := f.do(map[string]string{"Authorization": "JWT abc"})
	elapsed := time.Since(start)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want the request let through", rec.Code)
	}
	if elapsed > time.Second {
		t.Fatalf("request took %v, want it bounded near the 300ms connect deadline", elapsed)
	}
}

func TestUnexpectedReplyFailsOpenAndDiscardsConnection(t *testing.T) {
	f := newFixture(t, nil)
	f.srv.SetExists(redistest.Unexpected, 0)

	if rec := f.do(map[string]string{"Authorization": "JWT abc"}); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if f.handler.redisPool.Idle() != 0 {
		t.Fatal("a connection that returned an unexpected reply must not be pooled")
	}
}

func TestSlowRedisStepIsLoggedWithoutHeaderValues(t *testing.T) {
	f := newFixture(t, nil)
	// New() points the logger at stdout, so redirect it after building the fixture.
	var buf bytes.Buffer
	old := LoggerERROR.Writer()
	LoggerERROR.SetOutput(&buf)
	defer LoggerERROR.SetOutput(old)
	f.srv.SetExists(redistest.NotBlacklisted, 80*time.Millisecond)
	f.do(map[string]string{"Authorization": "JWT super-secret-token"})

	out := buf.String()
	if !strings.Contains(out, "slow redis step") {
		t.Fatalf("expected a slow-step log line, got %q", out)
	}
	if !strings.Contains(out, "authorization=true") || !strings.Contains(out, "developer_token=false") {
		t.Fatalf("log line should say which headers were present, got %q", out)
	}
	if strings.Contains(out, "super-secret-token") {
		t.Fatalf("log line leaked a token: %q", out)
	}
}

func TestFastRedisStepIsNotLogged(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.SlowLogMs = 1000 })
	var buf bytes.Buffer
	old := LoggerERROR.Writer()
	LoggerERROR.SetOutput(&buf)
	defer LoggerERROR.SetOutput(old)
	f.do(map[string]string{"Authorization": "JWT abc"})

	if strings.Contains(buf.String(), "slow redis step") {
		t.Fatalf("unexpected slow-step log: %q", buf.String())
	}
}

func TestOneDeadlineCoversBothTokens(t *testing.T) {
	// Each EXISTS takes 100ms, which fits in the 150ms budget alone but not
	// twice: the second token must run out of time and the request fail open.
	f := newFixture(t, nil)
	f.srv.SetExists(redistest.NotBlacklisted, 100*time.Millisecond)

	start := time.Now()
	rec := f.do(map[string]string{"Authorization": "JWT a", "Developer-token": "JWT b"})
	elapsed := time.Since(start)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want the request let through", rec.Code)
	}
	if elapsed > 190*time.Millisecond {
		t.Fatalf("request took %v, want it bounded by the single 150ms deadline", elapsed)
	}
	if f.handler.redisPool.Idle() != 0 {
		t.Fatal("a connection that hit the deadline must not be pooled")
	}
}
