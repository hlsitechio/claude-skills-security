---
name: fastapi-security
description: Security audit for FastAPI applications including dependency injection for auth, Pydantic schemas for input/output, OAuth2 scopes, async endpoint patterns, CORS middleware, SQL injection via SQLAlchemy raw queries, Starlette middleware, and FastAPI-specific patterns. Use this skill whenever the user mentions FastAPI, Pydantic, Starlette, OAuth2PasswordBearer, Depends, APIRouter, fastapi-users, SQLAlchemy in FastAPI, or asks "audit my FastAPI app", "FastAPI security review", "Pydantic safe". Trigger when the codebase contains `fastapi` in `requirements.txt` / `pyproject.toml`.
---

# FastAPI Security Audit

Audit FastAPI applications. FastAPI sits on Starlette + Pydantic — secure defaults are good, but custom code often bypasses them.

## When this skill applies

- Reviewing FastAPI endpoints, dependencies, Pydantic models
- Auditing OAuth2 / JWT / API key auth flows
- Reviewing CORS, middleware, exception handlers
- Checking SQLAlchemy / SQLModel usage for SQL injection
- Reviewing async patterns for race conditions

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection

```bash
grep -E '^fastapi|"fastapi"' requirements.txt pyproject.toml 2>/dev/null
python -c "import fastapi; print(fastapi.__version__)" 2>/dev/null
```

### Phase 2: Inventory

```bash
# Route definitions
grep -rn '@app\.\|@router\.' . --include='*.py' | head -50

# Dependencies (DI)
grep -rn 'Depends(' . --include='*.py' | head -30

# Pydantic models (schemas)
grep -rn 'class .*BaseModel\|class .*pydantic' . --include='*.py' | head

# CORS / middleware
grep -rn 'add_middleware\|CORSMiddleware\|TrustedHostMiddleware' . --include='*.py'

# Raw SQL
grep -rn 'text(\|execute(\|raw_connection' . --include='*.py'
```

### Phase 3: Detection — the checks

#### Pydantic schemas — input validation

- **FAP-PYD-1** Endpoints accepting request bodies declare a Pydantic model — never `request: dict` or `request: Any`.
- **FAP-PYD-2** Field constraints set: `Field(min_length=..., max_length=..., gt=..., lt=...)`.
- **FAP-PYD-3** `model_config = ConfigDict(extra='forbid')` (Pydantic v2) or `class Config: extra = 'forbid'` (v1) — rejects unknown fields, preventing mass assignment.
- **FAP-PYD-4** Email fields use `EmailStr`; URLs use `HttpUrl`; UUIDs use `UUID4`.

```python
from pydantic import BaseModel, ConfigDict, EmailStr, Field

class CreateUserIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    display_name: str = Field(min_length=1, max_length=50)
    # role is intentionally NOT here; set by server
```

#### Pydantic schemas — output filtering

- **FAP-PYD-5** Response model declared on endpoints to filter output:
  ```python
  @app.get("/users/{user_id}", response_model=UserOut)
  ```
  Without `response_model`, the endpoint returns whatever the function returns, including hidden fields.
- **FAP-PYD-6** Distinct input/output models (`UserIn`, `UserOut`, `UserInternal`) — don't reuse the same model for both directions; secrets leak.
- **FAP-PYD-7** `response_model_exclude` / `response_model_exclude_unset` not used to "hide" sensitive fields — explicit models are safer.

#### Authentication

- **FAP-AUTH-1** Every protected route declares an auth dependency:
  ```python
  @app.get("/me")
  async def me(user: User = Depends(get_current_user)):
      return user
  ```
- **FAP-AUTH-2** Global dependency for app-wide auth NOT mixed with per-route auth (confusing; pick one model).
- **FAP-AUTH-3** `OAuth2PasswordBearer` configured with `tokenUrl` matching the actual login endpoint.
- **FAP-AUTH-4** JWT validation: see `saas-security-pack/saas-code-security-review/references/jwt-validation.md`. Algorithm explicit, secret from env, expiry checked.
- **FAP-AUTH-5** Password hashing: `passlib[bcrypt]` or Argon2; not plain SHA-256.

```python
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)
```

#### Authorization

- **FAP-AUTHZ-1** Per-resource authz checked in the dependency or route body. Auth dependency returns `User`; the route must then check ownership / role for the specific resource.
- **FAP-AUTHZ-2** OAuth2 scopes (if used) checked via `Security(get_current_user, scopes=[...])`. Verify the dependency actually checks `security_scopes.scopes`.
- **FAP-AUTHZ-3** Admin routes guarded by a separate dependency, not just "is authenticated".

```python
def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Forbidden")
    return user

@app.delete("/admin/users/{user_id}")
async def delete_user(user_id: UUID, _: User = Depends(require_admin)):
    ...
```

#### CORS

- **FAP-CORS-1** `CORSMiddleware` with specific `allow_origins`, not `["*"]` for credentialed APIs.
- **FAP-CORS-2** `allow_credentials=True` ONLY with explicit origin list; with `*`, FastAPI/Starlette will block credentials, but ensure not bypassed via regex.
- **FAP-CORS-3** `allow_methods` and `allow_headers` not blanket `*` if not needed.

#### Trusted host

- **FAP-TH-1** `TrustedHostMiddleware` with `allowed_hosts` list — protects against Host header injection.

#### SQL injection (SQLAlchemy, SQLModel)

- **FAP-SQL-1** `session.execute(text("SELECT ..."))` with f-strings or `%` formatting = injection. Use bound params:
  ```python
  # BAD
  session.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))
  
  # GOOD
  session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})
  ```
- **FAP-SQL-2** SQLAlchemy Core / ORM `filter(User.id == user_id)` is parameterized — safe.
- **FAP-SQL-3** `query.filter(text(...))` patterns reviewed.

#### NoSQL injection

If using MongoDB / Beanie / Motor:
- **FAP-NOSQL-1** Don't pass dict directly from request to query: `users.find_one(request.json())` — attacker controls operators (`{"$gt": ""}`).

#### Async patterns

- **FAP-ASYNC-1** Endpoints declared `async def` use async DB clients; `sync_def` endpoints called via FastAPI's thread pool. Don't mix sync I/O in async endpoints (blocks event loop).
- **FAP-ASYNC-2** Shared mutable state (e.g., a module-level dict) accessed without locking → race conditions. Use Redis / DB / asyncio.Lock for shared state.

#### Background tasks

- **FAP-BG-1** `BackgroundTasks` for fire-and-forget; errors caught and logged, not silently swallowed.
- **FAP-BG-2** For long-running or critical background work, use Celery / Arq / Dramatiq — not BackgroundTasks (which dies with the worker process).

#### File uploads

- **FAP-UP-1** `UploadFile` reads streamed; size limits enforced (FastAPI doesn't enforce by default — use Starlette's `request.body` size limits or check size after read).
- **FAP-UP-2** Content type validated by magic bytes via `python-magic` or similar, not just `file.content_type` (client-controlled).
- **FAP-UP-3** File saved with sanitized filename (UUID + safe extension).

#### Error handling

- **FAP-ERR-1** Global exception handler in production hides stack traces.
- **FAP-ERR-2** `HTTPException` used for client errors; don't bubble Python exceptions verbatim.
- **FAP-ERR-3** Validation errors (422) don't echo full schema paths if they reveal internals — Pydantic v2 errors are typically OK, but customize if exposing column names becomes a concern.

#### OpenAPI / docs

- **FAP-DOC-1** `/docs` and `/redoc` disabled in production OR gated by auth:
  ```python
  app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
  ```
  Or:
  ```python
  app = FastAPI(openapi_url="/api/v1/openapi.json")
  # Then protect with router-level dependency
  ```
- **FAP-DOC-2** OpenAPI schema doesn't include example values that are real credentials.

#### Session and cookies

If using Starlette's `SessionMiddleware`:
- **FAP-SES-1** `secret_key` from env; not the example placeholder.
- **FAP-SES-2** `same_site='lax'`, `https_only=True` in production.

#### Dependencies

- **FAP-DEP-1** FastAPI, Pydantic, Starlette versions current. Pydantic v2 is significantly different from v1; verify migration was complete.
- **FAP-DEP-2** `pip-audit` clean.

### Phase 4: Triage

Critical: endpoint accepting arbitrary dict body without Pydantic; raw SQL with string formatting; CORS `*` with credentials; docs reachable in prod with sensitive endpoints visible.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `FAP-`.
