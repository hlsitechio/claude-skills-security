---
name: angular-security
description: Security audit for Angular applications including DomSanitizer bypassing (bypassSecurityTrust*), innerHTML binding, dynamic component loading, route guards (CanActivate, CanLoad), HttpClient interceptors, environment.ts file leakage, and Angular-specific patterns. Use this skill whenever the user mentions Angular, @angular/core, DomSanitizer, bypassSecurityTrustHtml, route guards, HttpInterceptor, environment.ts, Angular CLI, ng build, or asks "audit my Angular app", "Angular security review", "DomSanitizer safe". Trigger when the codebase contains `@angular/core` in package.json, `angular.json`, or `*.component.ts` files.
---

# Angular Security Audit

Audit Angular applications for framework-specific vulnerabilities. Covers Angular 14+ (modern), with notes on older.

## When this skill applies

- Reviewing Angular components for XSS
- Auditing DomSanitizer usage
- Reviewing route guards and authorization
- Checking HttpClient interceptors and CSRF setup
- Reviewing environment files for secret leakage

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection

```bash
grep -E '"@angular/core":' package.json
ng version 2>/dev/null
find . -name 'angular.json' -not -path '*/node_modules/*'
```

### Phase 2: Inventory

```bash
# XSS bypass sinks
grep -rn 'bypassSecurityTrust' src/

# innerHTML bindings
grep -rn '\[innerHTML\]' src/

# Route guards
grep -rn 'CanActivate\|CanLoad\|CanMatch\|canActivate' src/

# Interceptors
grep -rn 'HttpInterceptor\|provideHttpClient' src/

# Environment files
find src -name 'environment*.ts'
```

### Phase 3: Detection — the checks

#### DomSanitizer bypass

Angular auto-escapes interpolation. The bypass is `DomSanitizer.bypassSecurityTrust*`:

- **ANG-XSS-1** Every `bypassSecurityTrustHtml`, `bypassSecurityTrustScript`, `bypassSecurityTrustStyle`, `bypassSecurityTrustUrl`, `bypassSecurityTrustResourceUrl` reviewed. The "bypass" name is the warning.
- **ANG-XSS-2** Bypassed content from user input → Critical. Use `sanitize` instead of `bypassSecurityTrust*` unless the content is genuinely trusted.

```ts
// BAD
this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml(post.content);

// GOOD — Angular's default sanitization handles most cases
<div [innerHTML]="post.content"></div>  // Angular sanitizes here

// If you need richer HTML, use DOMPurify before binding
this.cleanHtml = DOMPurify.sanitize(post.content);
<div [innerHTML]="cleanHtml"></div>
```

#### innerHTML binding

`[innerHTML]="content"` triggers Angular's built-in sanitizer (strips scripts, on* handlers). Generally safe, but:

- **ANG-XSS-3** Angular's sanitizer strips `<script>` and event handlers but keeps `<img onerror>` neutralized; verify on a current Angular version (issues found and patched in older versions).
- **ANG-XSS-4** Markdown rendering libraries (`ngx-markdown`) configured with sanitization on; raw HTML option disabled.

#### Template injection

- **ANG-TPL-1** No `eval(...)` or `Function(...)` constructors with user input.
- **ANG-TPL-2** No dynamic template generation from user input (`Component.template = userValue` — rare, but a sink).

#### Route guards

- **ANG-RG-1** Routes that should be protected have guards (`CanActivate`, `CanMatch` in Angular 14.2+).
- **ANG-RG-2** Guards check auth state synchronously when possible OR use observables that resolve before navigation.
- **ANG-RG-3** Guards must not be the only check — backend endpoints serving data also enforce.
- **ANG-RG-4** Child routes inherit parent guards but verify: `canActivateChild` set where needed.

```ts
// app-routing.module.ts
const routes: Routes = [
  {
    path: 'admin',
    canActivate: [AdminGuard],
    canMatch: [AdminGuard],  // also prevents lazy-loading the module
    loadChildren: () => import('./admin/admin.module').then(m => m.AdminModule),
  },
];
```

#### HttpClient configuration

- **ANG-HTTP-1** Production builds use HTTPS URLs (`environment.production`'s `apiUrl` is `https://...`).
- **ANG-HTTP-2** `HttpClient` interceptors that add auth tokens scope correctly (don't send tokens to third-party hosts).

```ts
// BAD — sends Bearer token to any URL
intercept(req: HttpRequest<any>, next: HttpHandler) {
  const token = this.auth.getToken();
  return next.handle(req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }));
}

// GOOD — restrict to allowed origins
intercept(req: HttpRequest<any>, next: HttpHandler) {
  const isApi = req.url.startsWith(environment.apiUrl);
  if (!isApi) return next.handle(req);
  
  const token = this.auth.getToken();
  return next.handle(req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }));
}
```

- **ANG-HTTP-3** CSRF protection: if backend uses cookies, Angular's `HttpClientXsrfModule` configured (reads `XSRF-TOKEN` cookie, sends as `X-XSRF-TOKEN` header). The backend must set the cookie and validate the header.

#### Environment files

Angular's `environment.ts` and `environment.prod.ts` are bundled into the client:

- **ANG-ENV-1** No secrets in `environment.ts` / `environment.prod.ts`. Same trap as `VITE_*`. Build inspection:
  ```bash
  ng build --configuration production
  grep -rhoE 'apiSecret|.*SECRET.*|sk_(live|test)_' dist/ | sort -u
  ```
- **ANG-ENV-2** Configuration loaded at runtime via `APP_INITIALIZER` fetching `/config.json` from the host — for deploy-time config without rebuild.
- **ANG-ENV-3** Different `environment.*.ts` files don't include test/staging credentials that ship to production via misconfigured build target.

#### Angular Universal (SSR)

If using Angular SSR (`@nguniversal/express-engine` or modern Angular SSR):

- **ANG-SSR-1** Server-side code path doesn't leak request-scoped data into shared state visible to other users.
- **ANG-SSR-2** Pre-rendering: confirm pre-rendered HTML doesn't embed user-specific data.

#### Forms

- **ANG-FORM-1** Reactive forms with strong validators on inputs that reach the server (length, pattern, range).
- **ANG-FORM-2** Custom async validators that hit an endpoint don't enable user enumeration ("email already taken" reveals existence).

#### Lazy-loaded module config

- **ANG-LAZY-1** Lazy-loaded modules behind `canMatch` guard so unauthorized users don't even fetch the bundle (info disclosure prevented).

#### Dependencies

- **ANG-DEP-1** Angular version current; Angular 14, 15, 16, 17, 18, 19 are the supported lines. Older versions have unpatched CVEs.
- **ANG-DEP-2** `@angular/router` and `@angular/common` versions match the core version.
- **ANG-DEP-3** Common third-party libraries: `ng-bootstrap`, `primeng`, `ag-grid` — check for known issues.

### Phase 4: Triage

Critical: `bypassSecurityTrustHtml` with user input; route guard absent on admin routes with no backend check; API secret in environment.ts.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `ANG-`.
