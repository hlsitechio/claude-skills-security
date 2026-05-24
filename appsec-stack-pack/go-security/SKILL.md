---
name: go-security
description: Security audit for Go applications including net/http servers, Gin/Echo/Chi/Fiber frameworks, database/sql injection patterns, template auto-escape, context propagation, goroutine race conditions, file path handling with filepath.Join, and Go-specific patterns. Use this skill whenever the user mentions Go, golang, net/http, Gin, gin-gonic, Echo, labstack/echo, Chi, go-chi, Fiber, gofiber, database/sql, sqlx, GORM, html/template, or asks "audit my Go app", "Go security review", "gosec". Trigger when the codebase contains `go.mod`, `*.go` files, or Go in the deployment.
---

# Go Security Audit

Audit Go applications across stdlib `net/http`, Gin, Echo, Chi, Fiber.

## When this skill applies

- Reviewing Go HTTP handlers and middleware
- Auditing database queries (database/sql, sqlx, GORM)
- Reviewing template usage (html/template vs text/template)
- Checking goroutine safety and context propagation
- Reviewing file path handling

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection

```bash
grep -E '^module|require' go.mod | head
# Detect framework
grep -E 'github.com/(gin-gonic/gin|labstack/echo|go-chi/chi|gofiber/fiber|valyala/fasthttp)' go.mod
```

### Phase 2: Inventory

```bash
# Handlers and routes
grep -rn 'http\.HandleFunc\|r\.GET\|r\.POST\|router\.\|app\.' --include='*.go' . | head -50

# SQL queries
grep -rn 'db\.Query\|db\.QueryRow\|db\.Exec\|Prepare' --include='*.go' .

# Templates
grep -rn 'text/template\|html/template' --include='*.go' .

# File paths
grep -rn 'os\.Open\|filepath\.Join\|filepath\.Clean' --include='*.go' .

# Cryptography
grep -rn 'crypto/md5\|crypto/sha1\|crypto/des' --include='*.go' .
```

### Phase 3: Detection — the checks

#### Template injection

- **GOL-TPL-1** `html/template` used for HTML output (auto-escapes); never `text/template` for HTML (no escaping).
  ```go
  // BAD — text/template doesn't escape HTML
  import "text/template"
  tmpl, _ := text.Parse("<p>{{.Name}}</p>")
  
  // GOOD — html/template context-aware
  import "html/template"
  tmpl, _ := html.Parse("<p>{{.Name}}</p>")
  ```
- **GOL-TPL-2** No `template.HTML(userInput)`, `template.JS(userInput)`, `template.URL(userInput)` — these mark strings as safe and bypass escaping.
- **GOL-TPL-3** No `template.Parse(userInput)` — SSTI vulnerability.

#### SQL injection

- **GOL-SQL-1** `database/sql` uses `?` (MySQL) or `$1` (Postgres) placeholders:
  ```go
  // BAD
  rows, err := db.Query("SELECT * FROM users WHERE id = " + userID)
  
  // GOOD
  rows, err := db.Query("SELECT * FROM users WHERE id = $1", userID)
  ```
- **GOL-SQL-2** `fmt.Sprintf` constructing queries → injection.
- **GOL-SQL-3** GORM `Raw(sql, args)` parameterizes args; string concatenation does not.
- **GOL-SQL-4** Dynamic ORDER BY / table names → allowlist.

#### Path traversal

- **GOL-PATH-1** `filepath.Join(root, userInput)` does NOT prevent `..` traversal. After Join, verify result stays under root:
  ```go
  safeRoot, _ := filepath.Abs("/var/data/userfiles")
  target := filepath.Join(safeRoot, filepath.Clean(userInput))
  resolved, err := filepath.Abs(target)
  if err != nil || !strings.HasPrefix(resolved, safeRoot+string(filepath.Separator)) {
      return errForbidden
  }
  ```
- **GOL-PATH-2** Archive extraction (zip-slip): check each entry's resolved path stays inside the destination.

#### CORS

- **GOL-COR-1** CORS middleware configured with specific origins. In Gin: `cors.Default()` is `*`; use `cors.New(cors.Config{AllowOrigins: [...]})`.
- **GOL-COR-2** `AllowCredentials: true` combined with `AllowOrigins: ["*"]` is rejected by spec but check anyway.

#### Authentication

- **GOL-AUTH-1** JWT validation: parse with explicit signing method; reject `none`.
  ```go
  token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
      if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
          return nil, fmt.Errorf("unexpected signing method")
      }
      return []byte(jwtSecret), nil
  })
  ```
- **GOL-AUTH-2** Password hashing: `golang.org/x/crypto/bcrypt` or `argon2id`. Not MD5/SHA1/SHA256.
- **GOL-AUTH-3** Constant-time comparisons: `subtle.ConstantTimeCompare` for tokens, MACs.

#### Authorization

- **GOL-AZ-1** Per-handler middleware checks role/permission. Don't rely on URL routing for auth.
- **GOL-AZ-2** Ownership check uses values from validated session, not request body.

#### Middleware order (Gin/Chi/Echo)

- **GOL-MW-1** Recovery middleware registered first.
- **GOL-MW-2** Security headers (e.g., `secure.New()`) before routes.
- **GOL-MW-3** CORS before auth (CORS preflight must succeed without auth).
- **GOL-MW-4** Rate limiter before expensive parsing/handlers.

#### File uploads

- **GOL-UP-1** `r.ParseMultipartForm(maxMemory)` with bounded `maxMemory`.
- **GOL-UP-2** File size limited via `http.MaxBytesReader`.
- **GOL-UP-3** Content-type validated by sniffing (`http.DetectContentType` on bytes), not just `header.Header.Get("Content-Type")`.

#### TLS

- **GOL-TLS-1** Production servers use `http.Server` with TLS or terminate TLS at the reverse proxy with `Strict-Transport-Security` set.
- **GOL-TLS-2** `tls.Config.MinVersion: tls.VersionTLS12` (or 13).
- **GOL-TLS-3** Custom certificate verification disabled? `tls.Config.InsecureSkipVerify: true` is never OK in production.

#### Cryptography

- **GOL-CRYPTO-1** No `crypto/md5` or `crypto/sha1` for security purposes (passwords, MACs).
- **GOL-CRYPTO-2** Random number generation uses `crypto/rand`, NOT `math/rand` for security tokens.
- **GOL-CRYPTO-3** `crypto/des`, `crypto/rc4` not used.

#### SSRF

- **GOL-SSRF-1** `http.Get(userURL)` without URL validation → SSRF. See `saas-security-pack/saas-code-security-review/references/ssrf-patterns.md`.
- **GOL-SSRF-2** Custom `http.Client` with `Transport` that blocks internal IPs.

#### Goroutine and context

- **GOL-CTX-1** Handlers respect `r.Context()`; don't spawn goroutines without context for background work tied to request.
- **GOL-CTX-2** Long-running goroutines started from handlers don't leak (no shutdown signal).
- **GOL-CTX-3** Shared maps protected by `sync.Mutex` or use `sync.Map`; concurrent map access without sync is data race + panic.

#### Error handling

- **GOL-ERR-1** Errors not echoed verbatim to clients (`fmt.Fprintln(w, err)` leaks internals).
- **GOL-ERR-2** `panic` recovered at handler boundary (`gin.Recovery()`, `chi.Recoverer`, custom).
- **GOL-ERR-3** Stack traces logged server-side only.

#### Logging

- **GOL-LOG-1** No `log.Printf("token=%s", token)` — secrets not logged.
- **GOL-LOG-2** Structured logging (zap, zerolog, slog) with redaction for sensitive fields.

#### Static analysis

- **GOL-SAST-1** `gosec` run periodically. Common findings: hardcoded credentials, weak crypto, SQL injection patterns.
- **GOL-SAST-2** `staticcheck` and `go vet` clean in CI.

#### Dependencies

- **GOL-DEP-1** `go.mod` versions current; `go mod tidy` clean.
- **GOL-DEP-2** `govulncheck` clean — official Go vulnerability scanner.

### Phase 4: Triage

Critical: SQL via fmt.Sprintf; tls.InsecureSkipVerify in prod; SSRF reaching internal services; race condition on shared map.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `GOL-`.
