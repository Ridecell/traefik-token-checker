# Traefik Token Checker

**Traefik Token Checker** is a Traefik middleware plugin that inspects incoming HTTP requests for blacklisted JWT tokens or developer tokens stored in Redis. It acts as a gatekeeper, blocking requests with invalid or revoked tokens before they reach your backend services.

---
**There are two ways to develop plugins in Traefik:**

1.  **Wasm PlugPlugin:** 

    ⚠️  Limitation:
    - Runs in a sandbox — no network, no file access, no Redis.

    - Blocks all unsafe operations for security.

2.  **Yaegi Plugin:**

    ⚠️  Limitation:
    - Can’t use Redis Go libs like go-redis — they rely on features Yaegi doesn't support (like interfaces, reflection, cgo).

✅ Workaround
- Use raw TCP to talk to Redis directly (like your custom pool).

---

## 🔍 What It Does

This plugin intercepts HTTP requests and:
- Extracts `Authorization` and `Developer-token` headers.
- Parses the JWT token from these headers.
- Checks if the token is blacklisted by querying Redis using the RESP protocol.
- Blocks requests with blacklisted tokens and returns a 401 Unauthorized with a JSON error.

---

## 🚀 Use Cases

- Secure public APIs by rejecting blacklisted tokens.
- Centralized token revocation system with Redis.
- Enhance observability with built-in logging levels.

---

## 🧰 Configuration

Here are the available configuration options for this plugin:

| Key         | Description                          | Required | Default |
|-------------|--------------------------------------|----------|---------|
| `RedisURL` | Full Redis URL including password, e.g. redis://:mypassword@localhost:6379                    | ✅       | —       |
| `LogLevel`  | Logging level: `DEBUG`, `ERROR` | ❌       | `INFO`  |
| `IdleTimeInSeconds`  | Time duration in seconds to close connections from pool | ❌       | 50  |
| `PoolSize`  | Size of the connection pool | ❌       | 60 `s`  |
| `RedisTimeoutMs` | Deadline for the whole Redis lookup of one request (all tokens checked). On expiry the request is let through and the connection is closed | ❌ | 250 |
| `RedisConnectTimeoutMs` | Deadline for opening a Redis connection: TCP dial, TLS handshake and AUTH together | ❌ | 1000 |
| `SlowLogMs` | Log a `slow redis step` line when the whole Redis step of a request takes at least this long | ❌ | 100 |

### Example Configuration (Static)

```yaml
experimental:
  plugins:
    traefik-token-checker:
      moduleName: github.com/Ridecell/traefik-token-checker
      version: v1.0.0
```

## ⏱️ Behaviour when Redis is slow or unavailable

The blacklist check **fails open**: if Redis cannot be reached or does not answer in time, the request is forwarded instead of rejected.

- Every Redis operation has a deadline: connecting (`RedisConnectTimeoutMs`) and the lookup itself (`RedisTimeoutMs`, shared by all tokens checked for the request). A Redis server that stops answering therefore delays a request by at most `RedisConnectTimeoutMs + RedisTimeoutMs` (1.25 s with the defaults, and only when a new connection is needed), not until the operating system gives up on the connection.
- A connection that times out, errors or returns an unexpected reply is closed, never put back into the pool.
- Redis is only contacted for header values that start with `JWT `. Requests without such a header never take a connection from the pool.

When the Redis step of a request takes at least `SlowLogMs`, one `ERROR` level line is logged:

```
ERROR: tokenChecker: ... slow redis step: total=151ms get_conn=385µs authorization=true developer_token=false outcome=io_error
```

`outcome` is one of `ok`, `blacklisted`, `get_conn_error` or `io_error`. The line records durations and whether each header was present, never header or token values.
