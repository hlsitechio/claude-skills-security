---
name: flask-security
description: Security audit for Flask applications including Jinja2 autoescape bypass, Flask-Login session handling, Flask-WTF CSRF protection, Blueprint structure, app.config secrets, SQL via Flask-SQLAlchemy, file uploads, custom decorators for auth, and Flask-specific extensions. Use this skill whenever the user mentions Flask, flask app, Blueprint, Flask-Login, Flask-WTF, Flask-SQLAlchemy, Flask-RESTful, Flask-Admin, render_template, or asks "audit my Flask app", "Flask security review". Trigger when the codebase contains `flask` in `requirements.txt` / `pyproject.toml` or `from flask import` patterns.
---

# Flask Security Audit

Audit Flask applications. Flask is less opinionated than Django, so security depends heavily on developer choices.

## When this skill applies

- Reviewing Flask app structure, routes, blueprints
- Auditing Jinja2 templates for XSS
- Reviewing Flask-Login / Flask-WTF / Flask-SQLAlchemy setup
- Checking app.config for secret handling

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection

```bash
grep -E '^[Ff]lask|"flask"' requirements.txt pyproject.toml 2>/dev/null
python -c "import flask; print(flask.__version__)" 2>/dev/null
```

### Phase 2: Inventory

```bash
# App factory pattern
grep -rn 'def create_app\|Flask(__name__)' . --include='*.py' 2>/dev/null

# Routes
grep -rn '@app.route\|@.*\.route\|@bp\.' . --include='*.py' 2>/dev/null | head -50

# Templates
grep -rn 'render_template\|render_template_string' . --include='*.py' 2>/dev/null

# Jinja safe filter / autoescape
grep -rn '|safe\|autoescape\|Markup(' . --include='*.py' --include='*.html' 2>/dev/null

# Extensions
grep -nE 'flask-login|flask-wtf|flask-sqlalchemy|flask-restful|flask-admin|flask-cors' requirements.txt pyproject.toml 2>/dev/null
```

### Phase 3: Detection — the checks

#### App configuration

- **FLK-CFG-1** `SECRET_KEY` from env, not hardcoded. Generate with `secrets.token_urlsafe(64)`.
- **FLK-CFG-2** Different config classes for dev/prod, `DEBUG=False` in prod.
- **FLK-CFG-3** `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE='Lax'`.
- **FLK-CFG-4** `PERMANENT_SESSION_LIFETIME` set to a sensible value.
- **FLK-CFG-5** `WTF_CSRF_TIME_LIMIT` not `None` (or explicitly chosen).

```python
class ProductionConfig:
    SECRET_KEY = os.environ['FLASK_SECRET_KEY']
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
```

#### Templates — Jinja2 XSS

- **FLK-XSS-1** Jinja autoescape ON by default for `.html` files via `render_template`. Don't disable globally.
- **FLK-XSS-2** `{{ var|safe }}` filter and `{% autoescape false %}` reviewed — content must be trusted.
- **FLK-XSS-3** `Markup(user_input)` in Python flags user input as safe — same review needed.
- **FLK-XSS-4** `render_template_string(template, ...)` with user-controlled template → SSTI (Server-Side Template Injection). Critical vulnerability.

```python
# CRITICAL — SSTI
@app.route('/preview')
def preview():
    return render_template_string(request.args['template'])

# FIXED — render a static template, pass user input as variable
return render_template('preview.html', user_input=request.args['template'])
```

#### CSRF (Flask-WTF)

- **FLK-CSRF-1** `CSRFProtect(app)` initialized; protects all POST/PUT/DELETE by default.
- **FLK-CSRF-2** `{{ csrf_token() }}` in forms (or Flask-WTF's `{{ form.csrf_token }}`).
- **FLK-CSRF-3** API endpoints (JSON, token-auth) exempted via `@csrf.exempt` consciously, not because of CSRF failures.
- **FLK-CSRF-4** Webhook endpoints exempted but verified via signature (see `saas-security-pack/saas-api-security/references/webhook-security.md`).

#### Authentication (Flask-Login)

- **FLK-AUTH-1** `LoginManager.login_view` set; protected routes use `@login_required`.
- **FLK-AUTH-2** `current_user` checked in views for ownership / role.
- **FLK-AUTH-3** Password hashing: `werkzeug.security.generate_password_hash` (defaults to scrypt or pbkdf2) or `passlib` with Argon2/bcrypt.
- **FLK-AUTH-4** Login view rate-limited (per IP, per user). Flask-Limiter typically.
- **FLK-AUTH-5** `login_user(user, remember=True)` — remember-me tokens stored securely, can be revoked.
- **FLK-AUTH-6** `logout_user()` invalidates the server-side session.

#### Authorization

- **FLK-AZ-1** Per-resource ownership checks in view functions. `@login_required` only verifies authentication.
- **FLK-AZ-2** Role checks via custom decorator:
  ```python
  def admin_required(f):
      @wraps(f)
      def decorated(*args, **kwargs):
          if not current_user.is_authenticated or not current_user.is_admin:
              abort(403)
          return f(*args, **kwargs)
      return decorated
  ```

#### SQL (Flask-SQLAlchemy)

Same as FastAPI's SQLAlchemy section:
- **FLK-SQL-1** `db.session.execute(text(...))` with parameterized queries.
- **FLK-SQL-2** ORM filter expressions safe; raw string concatenation isn't.
- **FLK-SQL-3** `query.from_statement(text(...))` reviewed.

#### Mass assignment

- **FLK-MA-1** Don't pass `request.form` directly to `Model(**data)`. Use Flask-WTF Form (validates allowed fields) or Marshmallow schema.
- **FLK-MA-2** Updates via `setattr` over a dict require explicit allowlist.

#### File uploads

- **FLK-UP-1** `MAX_CONTENT_LENGTH` set (limits request size).
- **FLK-UP-2** `secure_filename(filename)` used on uploaded filenames.
- **FLK-UP-3** File type validated by content (magic bytes), not extension.
- **FLK-UP-4** Upload directory not in `static/` or any web-served path without auth.

#### CORS (flask-cors)

- **FLK-CORS-1** `CORS(app, origins=['https://app.yourorg.com'], supports_credentials=True)` — specific origins.
- **FLK-CORS-2** Not `CORS(app)` (wildcard).

#### Headers

Flask doesn't apply helmet-equivalent headers by default. Use Flask-Talisman:
- **FLK-HDR-1** `Talisman(app)` registered with appropriate CSP, HSTS, X-Content-Type-Options, etc.

```python
from flask_talisman import Talisman
Talisman(app, content_security_policy={
    'default-src': "'self'",
    'img-src': ["'self'", 'data:', 'https://images.yourcdn.com'],
    # ...
})
```

#### Debugging and error pages

- **FLK-DBG-1** Werkzeug debugger NEVER enabled in production. `app.debug = False`, `app.run(debug=False)`.
- **FLK-DBG-2** Custom error handlers for 404, 500 don't leak internal details.
- **FLK-DBG-3** `app.config['PROPAGATE_EXCEPTIONS']` not unintentionally True in prod.

The Werkzeug debugger PIN-protected console can be brute-forced; absolutely never expose to production.

#### Flask-Admin

- **FLK-ADM-1** Flask-Admin views protected with auth check (`is_accessible` method on ModelView).
- **FLK-ADM-2** Admin URL not at predictable `/admin/`; access logged.
- **FLK-ADM-3** Sensitive columns excluded from Flask-Admin display (passwords, secrets).

#### Blueprints

- **FLK-BP-1** Blueprints with `url_prefix='/api'` etc. — auth applied at blueprint level via `@blueprint.before_request`.
- **FLK-BP-2** `url_for` used consistently; no hardcoded URLs that could lead to open redirects.

#### Open redirects

- **FLK-OR-1** `redirect(url)` with `url` from `request.args.get('next')` validated against allowlist or relative-only:
  ```python
  from urllib.parse import urlparse
  next_url = request.args.get('next', '/')
  if urlparse(next_url).netloc:
      next_url = '/'   # external origin not allowed
  return redirect(next_url)
  ```

#### Dependencies

- **FLK-DEP-1** Flask version current (3.x).
- **FLK-DEP-2** Werkzeug version matches Flask requirements. CVE-2024-34069 (Werkzeug debugger pin bypass on certain configs) — bump Werkzeug.
- **FLK-DEP-3** `pip-audit` clean.

### Phase 4: Triage

Critical: Werkzeug debugger reachable; SSTI via render_template_string; `SECRET_KEY` hardcoded; CSRF disabled globally.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `FLK-`.
