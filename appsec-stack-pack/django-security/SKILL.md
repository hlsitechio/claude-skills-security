---
name: django-security
description: Security audit for Django applications including settings.py (SECRET_KEY, DEBUG, ALLOWED_HOSTS), middleware order, ORM raw queries, template autoescape bypass, CSRF protection, Django Admin exposure, authentication backends, file upload handling, and Django-specific patterns. Use this skill whenever the user mentions Django, settings.py, manage.py, Django ORM, Django REST Framework, DRF, makemigrations, urls.py, views.py, or asks "audit my Django app", "Django security review", "Django settings safe". Trigger when the codebase contains `django` in `requirements.txt` / `pyproject.toml`, or `manage.py`, `settings.py`, `urls.py` files.
---

# Django Security Audit

Audit Django applications including DRF (Django REST Framework) APIs.

## When this skill applies

- Reviewing Django `settings.py` files
- Auditing views, models, and templates
- Reviewing DRF serializers and viewsets
- Checking authentication and permission classes
- Auditing Django Admin exposure

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection

```bash
grep -E '^Django|django' requirements.txt pyproject.toml 2>/dev/null
find . -name 'manage.py' -not -path '*/.venv/*'
find . -name 'settings.py' -o -name 'settings/*.py' 2>/dev/null
python -c "import django; print(django.get_version())" 2>/dev/null
```

### Phase 2: Inventory

```bash
# Settings files
find . -name 'settings*.py' -not -path '*/.venv/*' -not -path '*/node_modules/*'

# Views
find . -name 'views.py' -o -name 'views/' -type d 2>/dev/null

# URL configurations
find . -name 'urls.py' 2>/dev/null

# Raw SQL usage
grep -rn '\.raw(\|cursor()\|connection\.cursor' . --include='*.py' 2>/dev/null

# Template autoescape disabling
grep -rn '|safe\|autoescape off\|mark_safe\|format_html' . --include='*.py' --include='*.html' 2>/dev/null
```

### Phase 3: Detection — the checks

#### `settings.py` audit

- **DJG-SET-1** `SECRET_KEY` from environment variable, not committed:
  ```python
  SECRET_KEY = os.environ['DJANGO_SECRET_KEY']
  ```
  Audit: `git log -p settings.py | grep -i secret_key` — if any historical commit has a real secret, rotate.
- **DJG-SET-2** `DEBUG = False` in production. Confirmed via env-based settings split:
  ```python
  DEBUG = os.environ.get('DJANGO_DEBUG', '0') == '1'
  ```
- **DJG-SET-3** `ALLOWED_HOSTS` not `['*']` in production. Specific hostnames listed.
- **DJG-SET-4** `SECURE_*` settings configured:
  - `SECURE_SSL_REDIRECT = True`
  - `SESSION_COOKIE_SECURE = True`
  - `CSRF_COOKIE_SECURE = True`
  - `SECURE_HSTS_SECONDS = 31536000` (or more)
  - `SECURE_HSTS_INCLUDE_SUBDOMAINS = True`
  - `SECURE_HSTS_PRELOAD = True` (if you want preload list inclusion)
  - `SECURE_CONTENT_TYPE_NOSNIFF = True`
  - `SECURE_BROWSER_XSS_FILTER` — removed in Django 4 (XSS-Protection deprecated); use CSP instead
  - `X_FRAME_OPTIONS = 'DENY'` (or 'SAMEORIGIN')
- **DJG-SET-5** `CSRF_TRUSTED_ORIGINS` lists specific origins (not `*`).
- **DJG-SET-6** `DATABASES` config uses env vars for credentials.
- **DJG-SET-7** `EMAIL_*` config doesn't have plaintext credentials.
- **DJG-SET-8** `MIDDLEWARE` order:
  ```python
  MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',          # 1st
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',                  # before CommonMiddleware
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
  ]
  ```

#### CSRF

- **DJG-CSRF-1** `CsrfViewMiddleware` in MIDDLEWARE.
- **DJG-CSRF-2** No `@csrf_exempt` on state-changing views unless explicitly needed and documented (webhooks with their own signature verification are OK).
- **DJG-CSRF-3** DRF views using `SessionAuthentication` automatically apply CSRF. Token/JWT auth doesn't (and shouldn't, for non-cookie auth).

#### ORM and raw SQL

- **DJG-ORM-1** `.raw(sql, params)` uses parameterized queries (the `params` list). String concatenation is SQL injection.
  ```python
  # BAD
  User.objects.raw(f"SELECT * FROM auth_user WHERE id = {user_id}")
  
  # GOOD
  User.objects.raw("SELECT * FROM auth_user WHERE id = %s", [user_id])
  ```
- **DJG-ORM-2** `connection.cursor()` queries use parameterized queries.
- **DJG-ORM-3** `extra(where=[...])` with user input is injection-prone; prefer `Q()` filters.
- **DJG-ORM-4** `objects.filter(...)` with field lookups is safe; the ORM parameterizes.

#### Mass assignment

- **DJG-MA-1** `Model.objects.create(**request.POST)` patterns flagged. Use forms / serializers with explicit field allowlists.
- **DJG-MA-2** DRF `ModelSerializer` with `fields = '__all__'` is mass-assignable. Use explicit `fields = ['id', 'name', ...]`.
- **DJG-MA-3** Form `Meta.fields` and `Meta.exclude` reviewed.

#### Templates

- **DJG-TPL-1** Django templates auto-escape by default. `{{ var|safe }}` filter and `{% autoescape off %}` disable it — review every occurrence.
- **DJG-TPL-2** `mark_safe(...)` and `format_html(...)` in Python code mark strings as safe — confirm content is trusted.
- **DJG-TPL-3** SSTI: don't render user input as a template (`Template(user_input).render(...)`).

#### Authentication

- **DJG-AUTH-1** `AUTH_PASSWORD_VALIDATORS` configured with reasonable validators.
- **DJG-AUTH-2** `PASSWORD_HASHERS` first entry is Argon2 or BCrypt (Django default Argon2 is good).
- **DJG-AUTH-3** Custom backends (subclasses of `BaseBackend`) review `authenticate()` for timing attacks.
- **DJG-AUTH-4** `django.contrib.auth.password_validation.validate_password` called before set_password.

#### DRF (Django REST Framework)

- **DJG-DRF-1** Global `DEFAULT_PERMISSION_CLASSES` set to `IsAuthenticated` (or stricter); not `AllowAny`.
- **DJG-DRF-2** Per-view permission classes set; no view relying solely on URL routing for auth.
- **DJG-DRF-3** `ViewSet.queryset` filtered to tenant/user scope, not returning all objects.
- **DJG-DRF-4** Serializers define `fields` explicitly, exclude sensitive (`password`, `is_superuser`, `user_permissions` if not needed).
- **DJG-DRF-5** Throttling configured (`DEFAULT_THROTTLE_RATES`).

```python
# REST_FRAMEWORK settings.py snippet
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.IsAuthenticated'],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.UserRateThrottle',
        'rest_framework.throttling.AnonRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'user': '1000/hour',
        'anon': '100/hour',
    },
}
```

#### File uploads

- **DJG-UP-1** `FILE_UPLOAD_MAX_MEMORY_SIZE` and `DATA_UPLOAD_MAX_MEMORY_SIZE` set.
- **DJG-UP-2** `FILE_UPLOAD_PERMISSIONS` restrictive (0o644).
- **DJG-UP-3** `MEDIA_ROOT` not within web-served path that could expose uploaded files without auth.
- **DJG-UP-4** Uploaded file validated by content (magic bytes), not just `content_type`.

#### Django Admin

- **DJG-ADM-1** Admin reachable only by staff users (`is_staff=True`).
- **DJG-ADM-2** Admin URL changed from `/admin/` to a less-discoverable path (defense in depth).
- **DJG-ADM-3** Admin behind VPN / IP allowlist for production sites with regular user traffic.
- **DJG-ADM-4** Custom admin actions reviewed for unintended privilege.

#### Static and media files

- **DJG-STA-1** `DEBUG = False` means Django doesn't serve static files; deployed via nginx / S3 / CloudFront — confirm headers set there.
- **DJG-STA-2** `collectstatic` output doesn't include accidentally-committed sensitive files.

#### Logging

- **DJG-LOG-1** Logging config doesn't include `'level': 'DEBUG'` for production. Don't log request bodies containing PII.
- **DJG-LOG-2** Django's default email-error-to-admins (when DEBUG=False) sends tracebacks — verify recipients are correct, no broad mailing lists.

#### Dependencies

- **DJG-DEP-1** Django version is on a current Long Term Support (LTS) line (4.2 LTS, 5.2 LTS) or current main. Old versions unpatched.
- **DJG-DEP-2** `pip list --outdated` reviewed. `safety check` or `pip-audit` run periodically.

### Phase 4: Triage

Critical: `DEBUG = True` in production; `ALLOWED_HOSTS = ['*']`; raw query with string concatenation; admin publicly accessible with weak password policy.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `DJG-`.
