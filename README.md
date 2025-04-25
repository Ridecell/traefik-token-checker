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

### Example Configuration (Static)

```yaml
experimental:
  plugins:
    traefik-token-checker:
      moduleName: github.com/Ridecell/traefik-token-checker
      version: v1.0.0
