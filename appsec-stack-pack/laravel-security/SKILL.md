---
name: laravel-security
description: Security audit for Laravel PHP applications including Eloquent mass assignment ($fillable/$guarded), middleware (auth, throttle, csrf), Blade template safety, validation rules, Sanctum/Passport auth, .env handling, query builder safety, and Laravel-specific patterns. Use this skill whenever the user mentions Laravel, php artisan, Eloquent, Blade, Sanctum, Passport, Tinker, Forge, Vapor, or asks "audit my Laravel app", "Laravel security review". Trigger when the codebase contains `composer.json` with `laravel/framework`, `artisan` file, or `app/Http/` directory.
---

# Laravel Security Audit

Audit Laravel PHP applications (9, 10, 11, 12).

## When this skill applies

- Reviewing Laravel models, controllers, requests, middleware
- Auditing mass assignment patterns
- Reviewing Blade templates for XSS
- Checking auth setup (Sanctum, Passport, Breeze, Jetstream)
- Auditing `.env` handling and config caching

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection

```bash
grep -E '"laravel/framework"' composer.json
php artisan --version 2>/dev/null
```

### Phase 2: Inventory

```bash
# Models
find app/Models -name '*.php' 2>/dev/null

# Controllers
find app/Http/Controllers -name '*.php' | head

# Middleware
find app/Http/Middleware -name '*.php'

# Routes
cat routes/web.php routes/api.php 2>/dev/null | head -100

# Auth config
cat config/auth.php 2>/dev/null

# .env presence and gitignore
cat .gitignore | grep -i env
```

### Phase 3: Detection — the checks

#### Eloquent mass assignment

- **LRV-MA-1** Every Eloquent model has `$fillable` (allowlist) or `$guarded` set. Default `$guarded = []` allows everything.
- **LRV-MA-2** Sensitive fields (`password`, `is_admin`, `email_verified_at`, foreign keys to other users) NOT in `$fillable`.
- **LRV-MA-3** No `Model::unguard()` or `Model::unguarded(fn() => ...)` in production paths.

```php
class User extends Model {
    // GOOD — explicit allow-list
    protected $fillable = ['name', 'email'];
    
    // password is set via setPasswordAttribute (mutator) with bcrypt
    // is_admin is NEVER mass-assignable
}
```

#### Validation

- **LRV-VAL-1** Form Request classes (`php artisan make:request`) used for input validation, not inline `$request->validate(...)` everywhere (centralizes rules).
- **LRV-VAL-2** Rules include format constraints: `email`, `url`, `uuid`, `min`, `max`, `regex`.
- **LRV-VAL-3** `nullable` only on truly optional fields.
- **LRV-VAL-4** `exists:table,column` rule used to validate foreign keys (catches non-existent IDs before query).

#### SQL injection

- **LRV-SQL-1** Query Builder uses bindings:
  ```php
  // GOOD
  DB::select('SELECT * FROM users WHERE id = ?', [$id]);
  User::where('id', $id)->first();
  
  // BAD
  DB::select("SELECT * FROM users WHERE id = $id");
  ```
- **LRV-SQL-2** `whereRaw('column = ' . $value)` is injection. Use `whereRaw('column = ?', [$value])`.
- **LRV-SQL-3** Dynamic column names → allowlist (Builder doesn't parameterize identifiers).
- **LRV-SQL-4** `orderBy($request->sort)` without allowlist → injection on identifier.

#### Blade XSS

- **LRV-XSS-1** `{{ $var }}` auto-escapes. `{!! $var !!}` does NOT — review every usage.
- **LRV-XSS-2** `@php` blocks with `echo` lose auto-escape; check `e()` is called.
- **LRV-XSS-3** `Html::raw(...)` (laravel-collective/html) is the same risk as `{!! !!}`.

#### CSRF

- **LRV-CSRF-1** `VerifyCsrfToken` middleware in `web` group applies to forms.
- **LRV-CSRF-2** `@csrf` directive in all forms.
- **LRV-CSRF-3** `$except` array in `VerifyCsrfToken` reviewed — webhook endpoints there should have signature verification.
- **LRV-CSRF-4** API routes (auth via Sanctum/Passport tokens) don't use the web CSRF; verify auth still robust.

#### Authentication

- **LRV-AUTH-1** Password hashing via `Hash::make($password)` — uses Bcrypt by default (or Argon2 if configured).
- **LRV-AUTH-2** `auth` middleware on protected routes.
- **LRV-AUTH-3** Sanctum: API tokens stored hashed; `personal_access_tokens` table has the hash.
- **LRV-AUTH-4** Passport: client secrets stored hashed.
- **LRV-AUTH-5** Password reset throttled, tokens single-use.
- **LRV-AUTH-6** Login throttle middleware applied to login route (default `throttle:login` in 10+).
- **LRV-AUTH-7** Email verification (`MustVerifyEmail`) on sensitive routes.

#### Authorization (Policies, Gates)

- **LRV-AZ-1** Each model has a Policy class; controller actions call `$this->authorize('update', $post)`.
- **LRV-AZ-2** `Gate::define` checks not bypassed by skipping `authorize` in controller.
- **LRV-AZ-3** Resource controller has policy bindings (`apiResource` with policy).

#### File uploads

- **LRV-UP-1** `php.ini` `upload_max_filesize` and `post_max_size` set sensibly at the PHP level.
- **LRV-UP-2** Validation rule `'file' => 'required|mimes:jpg,png,pdf|max:2048'` — `mimes` validates MIME type from extension; for stronger checks use `mimetypes` rule.
- **LRV-UP-3** `$request->file()->store(...)` — files stored in private disk by default; serving requires signed URLs or auth-gated routes.
- **LRV-UP-4** Filenames sanitized (Laravel's `store()` generates random names by default — safe; don't override with original name).

#### `.env` and config

- **LRV-ENV-1** `.env` in `.gitignore`. Verify with `git log .env` — should be empty.
- **LRV-ENV-2** `APP_KEY` set (`php artisan key:generate`). Same key across all instances.
- **LRV-ENV-3** `APP_DEBUG=false` in production. Debug mode shows stack traces with .env variables.
- **LRV-ENV-4** `php artisan config:cache` after deployment so .env changes propagate.
- **LRV-ENV-5** `config/services.php` etc. read from `env()` ONLY in config files (not in code outside config) so caching works.

#### Cookies and sessions

- **LRV-CK-1** `config/session.php` — `secure => true, http_only => true, same_site => 'lax'`.
- **LRV-CK-2** Session driver in production not `array` or `file` (single-instance only); use Redis / DB / Memcached.
- **LRV-CK-3** `lifetime` reasonable; not days for sensitive apps.

#### Logging

- **LRV-LOG-1** No `Log::info($request->all())` patterns that include passwords/tokens.
- **LRV-LOG-2** Production log channel doesn't include `daily` driver with no rotation/retention.

#### Headers

- **LRV-HDR-1** Middleware that sets security headers (custom or `bepsvpt/secure-headers` package).
- **LRV-HDR-2** HTTPS enforced via middleware or web server.

#### Open redirects

- **LRV-OR-1** `redirect()->to($request->next)` with external URL → open redirect. Validate or use `intended()` with allowlisted fallback.

#### Deserialization

- **LRV-DES-1** No `unserialize($userInput)` without `allowed_classes` option.
- **LRV-DES-2** `Crypt::decrypt` on user input safe (signed) — but the content inside must still be validated.

#### Telescope / Debugbar in production

- **LRV-DBG-1** Laravel Telescope disabled in production OR access-restricted to specific users.
- **LRV-DBG-2** Laravel Debugbar disabled in production (`APP_DEBUG=false` typically handles).

#### Dependencies

- **LRV-DEP-1** Laravel version current (10, 11, 12 supported lines).
- **LRV-DEP-2** `composer audit` clean.

### Phase 4: Triage

Critical: `$guarded = []` on user model + admin flag; `whereRaw` with user input concatenated; Telescope in production publicly accessible; `APP_DEBUG=true` in prod.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `LRV-`.
