---
name: rails-security
description: Security audit for Ruby on Rails applications including strong parameters / mass assignment, ActiveRecord SQL injection, ERB template safety, CSRF protection_from_forgery, Devise authentication, CanCanCan/Pundit authorization, secret_key_base, credentials.yml.enc, and Rails-specific patterns. Use this skill whenever the user mentions Ruby on Rails, Rails 6/7/8, ActiveRecord, ActiveAdmin, Devise, Pundit, CanCanCan, strong_parameters, ERB, Brakeman, or asks "audit my Rails app", "Rails security review", "Brakeman". Trigger when the codebase contains `Gemfile`, `config/application.rb`, or `rails` in dependencies.
---

# Ruby on Rails Security Audit

Audit Rails applications (Rails 6, 7, 8).

## When this skill applies

- Reviewing controllers, models, views
- Auditing strong parameters / mass assignment
- Reviewing ActiveRecord queries for injection
- Checking Devise / Pundit / CanCanCan setup
- Auditing secrets and credential management

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection

```bash
grep -E "rails" Gemfile | head
bundle exec rails --version 2>/dev/null
```

### Phase 2: Inventory

```bash
# Controllers
find app/controllers -name '*.rb' | head

# Models
find app/models -name '*.rb' | head

# Routes
cat config/routes.rb 2>/dev/null | head -100

# Initializers (security-relevant)
ls config/initializers/

# Brakeman recommended
which brakeman 2>/dev/null || echo "Install: gem install brakeman"
```

### Phase 3: Detection — the checks

#### Strong parameters

- **RLS-SP-1** Every controller action accepting params for create/update uses a `permit` allowlist:
  ```ruby
  def user_params
    params.require(:user).permit(:email, :name)
    # role, admin flags explicitly NOT in permit
  end
  ```
- **RLS-SP-2** No `params.permit!` (allows everything — equivalent to no protection).
- **RLS-SP-3** Nested attributes use `permit(:foo, addresses_attributes: [:street, :city])` not `permit!`.

#### SQL injection (ActiveRecord)

- **RLS-SQL-1** `where("name = '#{params[:name]}'")` is injection. Use placeholders:
  ```ruby
  User.where("name = ?", params[:name])
  User.where(name: params[:name])
  ```
- **RLS-SQL-2** Dynamic ORDER BY: `User.order(params[:sort])` — Rails 6+ raises on unknown columns, but the safe path is `User.order(sort_column => sort_direction)` with allowlisted values.
- **RLS-SQL-3** `find_by_sql("SELECT * WHERE id = #{params[:id]}")` is injection. Use placeholders.
- **RLS-SQL-4** Raw SQL via `connection.execute` reviewed.

#### Template XSS (ERB)

- **RLS-XSS-1** ERB auto-escapes `<%= %>`. `<%== %>` (double equals) and `raw(...)`, `html_safe`, `.html_safe` skip escaping.
- **RLS-XSS-2** `sanitize(html, ...)` used for partial HTML; safer than `raw`.
- **RLS-XSS-3** `link_to(text, params[:url])` — Rails normalizes `javascript:` URLs in `link_to`? Confirm — depends on version; validate URLs server-side.
- **RLS-XSS-4** `content_tag(:a, name, href: params[:url])` does not validate URL.

#### CSRF

- **RLS-CSRF-1** `protect_from_forgery with: :exception` in ApplicationController (Rails 5+ default; verify not removed).
- **RLS-CSRF-2** API-only controllers (`ActionController::API`) skip CSRF by default — verify auth is token/JWT-based (not cookie).
- **RLS-CSRF-3** No `skip_before_action :verify_authenticity_token` on state-changing endpoints unless replaced with equivalent (webhook signatures).
- **RLS-CSRF-4** Rails 7+ `Origin` check by default for non-GET; verify config.

#### Authentication (Devise)

- **RLS-AUTH-1** Devise modules appropriate: `:database_authenticatable`, `:registerable`, `:recoverable`, `:trackable`, `:lockable`, `:timeoutable`, `:validatable`.
- **RLS-AUTH-2** `:lockable` enabled to prevent brute force.
- **RLS-AUTH-3** Password reset tokens single-use and time-limited (Devise defaults reasonable).
- **RLS-AUTH-4** Email enumeration prevented: same response for "email sent" whether or not the email exists.
- **RLS-AUTH-5** `before_action :authenticate_user!` on protected controllers.

#### Authorization (Pundit / CanCanCan)

- **RLS-AZ-1** Every controller action uses `authorize @resource` (Pundit) or `load_and_authorize_resource` (CanCanCan).
- **RLS-AZ-2** Pundit's `verify_authorized` and `verify_policy_scoped` in `after_action` to catch missed authz.
- **RLS-AZ-3** Policy scopes restrict index queries to current_user-visible.
- **RLS-AZ-4** Default-deny: missing policies → 403.

```ruby
class ApplicationController < ActionController::Base
  include Pundit::Authorization
  
  after_action :verify_authorized, except: :index
  after_action :verify_policy_scoped, only: :index
  
  rescue_from Pundit::NotAuthorizedError, with: :user_not_authorized
  
  private
  def user_not_authorized
    render plain: 'Forbidden', status: :forbidden
  end
end
```

#### Mass assignment via attribute hash

- **RLS-MA-1** `User.new(params[:user])` without strong params = mass assignment.
- **RLS-MA-2** `User.update(params[:user])` similarly.
- **RLS-MA-3** `attr_accessible` / `attr_protected` (deprecated; pre-Rails 4) not relied on.

#### Open redirects

- **RLS-OR-1** `redirect_to params[:return_to]` — validate the URL against allowlist or use `redirect_to params[:return_to], allow_other_host: false` (Rails 7+ default for safety).
- **RLS-OR-2** Devise `after_sign_in_path_for` doesn't blindly use `stored_location_for`.

#### Insecure deserialization

- **RLS-DES-1** `Marshal.load(user_input)` is RCE. Never deserialize untrusted data with Marshal.
- **RLS-DES-2** `YAML.load(user_input)` (not safe) → RCE. Use `YAML.safe_load`.
- **RLS-DES-3** `JSON.load` invokes `Object.from_json` and is unsafe; use `JSON.parse`.

#### Secrets and credentials

- **RLS-SEC-1** `config/credentials.yml.enc` encrypted; `master.key` not committed (in `.gitignore`).
- **RLS-SEC-2** `Rails.application.credentials.secret_key_base` set in production.
- **RLS-SEC-3** Environment-specific credentials (`config/credentials/production.yml.enc`) used.
- **RLS-SEC-4** No secrets in `config/secrets.yml` (deprecated) committed.

#### Cookies and sessions

- **RLS-CK-1** Session store config secure: `Rails.application.config.session_store :cookie_store, key: ..., secure: true, httponly: true, same_site: :lax`.
- **RLS-CK-2** Cookie store has size limit (4KB); if storing large data, use Redis/DB store.
- **RLS-CK-3** Signed/encrypted cookies used for sensitive data (`cookies.signed[:foo]`, `cookies.encrypted[:foo]`).

#### File uploads (Active Storage, CarrierWave, Shrine)

- **RLS-UP-1** Active Storage's allowlist of content types if exposing direct uploads.
- **RLS-UP-2** Active Storage variants and previews not run on untrusted content (ImageMagick CVEs).
- **RLS-UP-3** S3 / blob URLs not directly user-controllable.

#### Rails Admin / ActiveAdmin

- **RLS-ADM-1** Admin gem authentication enforced separately from app auth.
- **RLS-ADM-2** Admin actions audited (paper_trail, audited gem).
- **RLS-ADM-3** Admin URL changed from default `/admin` for security through obscurity.

#### Headers

- **RLS-HDR-1** `config.force_ssl = true` in production.
- **RLS-HDR-2** Custom CSP via `config.content_security_policy` block.
- **RLS-HDR-3** `secure_headers` gem or Rails defaults for X-Frame-Options, X-Content-Type-Options.

#### Brakeman

- **RLS-BR-1** Brakeman run in CI. `brakeman --no-pager -A` should pass with high/critical confidence findings = 0.
- **RLS-BR-2** Brakeman ignores (`config/brakeman.ignore`) reviewed; false positives documented.

#### Dependencies

- **RLS-DEP-1** `bundle update` recent; Gemfile.lock current.
- **RLS-DEP-2** `bundle audit` clean.
- **RLS-DEP-3** Rails version current LTS; old versions unpatched.

### Phase 4: Triage

Critical: `params.permit!` on user model; `YAML.load(user_input)`; raw SQL with string interpolation; CSRF disabled globally.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `RLS-`.
