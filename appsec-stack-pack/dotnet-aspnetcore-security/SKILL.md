---
name: dotnet-aspnetcore-security
description: Security audit for ASP.NET Core applications including authentication middleware ordering, [Authorize] attribute usage, antiforgery, model binding (overposting), EF Core raw queries, data protection key management, appsettings.json secrets, identity/JWT setup, and .NET-specific patterns. Use this skill whenever the user mentions ASP.NET Core, .NET, dotnet, [Authorize], EF Core, Entity Framework, appsettings.json, IdentityServer, JWT in .NET, Minimal API, or asks "audit my .NET app", "ASP.NET Core security review". Trigger when the codebase contains `*.csproj`, `Program.cs`, `Startup.cs`, or `appsettings*.json`.
---

# ASP.NET Core Security Audit

Audit ASP.NET Core applications (.NET 6, 7, 8, 9).

## When this skill applies

- Reviewing ASP.NET Core middleware pipeline
- Auditing controllers / Minimal API endpoints
- Reviewing EF Core for SQL injection
- Checking authentication / authorization setup
- Auditing `appsettings.json` for secret handling

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection

```bash
find . -name '*.csproj' -not -path '*/bin/*' -not -path '*/obj/*'
find . -name 'Program.cs' -not -path '*/bin/*' -not -path '*/obj/*'
dotnet --version 2>/dev/null
```

### Phase 2: Inventory

```bash
# Middleware pipeline
grep -rn 'app\.Use\|app\.Map\|builder\.Services' Program.cs Startup.cs 2>/dev/null

# Authorize attributes
grep -rn '\[Authorize\|\[AllowAnonymous' . --include='*.cs'

# EF queries
grep -rn 'FromSqlRaw\|ExecuteSqlRaw\|FromSqlInterpolated' . --include='*.cs'

# Configuration
ls appsettings*.json 2>/dev/null
```

### Phase 3: Detection — the checks

#### Middleware pipeline order

```csharp
// Program.cs (.NET 6+ minimal hosting)
var app = builder.Build();

app.UseHttpsRedirection();
app.UseHsts();              // HSTS
app.UseStaticFiles();       // Static files before auth (intentional)
app.UseRouting();
app.UseCors(policyName);    // After routing, before auth
app.UseAuthentication();    // Authentication
app.UseAuthorization();     // Authorization (after authentication)
app.UseAntiforgery();       // .NET 8+ explicit
app.MapControllers();
app.Run();
```

- **DNC-MW-1** `UseAuthentication` before `UseAuthorization`. Reverse = authorization runs before identity is set.
- **DNC-MW-2** `UseCors` between `UseRouting` and `UseAuthorization`.
- **DNC-MW-3** `UseHsts` enabled in production (typically inside `if (!app.Environment.IsDevelopment())`).
- **DNC-MW-4** `UseHttpsRedirection` so HTTP → HTTPS.

#### Authentication

- **DNC-AUTH-1** `builder.Services.AddAuthentication(...)` configured; scheme matches what controllers expect.
- **DNC-AUTH-2** JWT: `AddJwtBearer` configured with `TokenValidationParameters`:
  ```csharp
  options.TokenValidationParameters = new TokenValidationParameters {
      ValidateIssuer = true,
      ValidateAudience = true,
      ValidateLifetime = true,
      ValidateIssuerSigningKey = true,
      ValidIssuer = config["Jwt:Issuer"],
      ValidAudience = config["Jwt:Audience"],
      IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"])),
      ClockSkew = TimeSpan.Zero,  // optional, tighter
  };
  ```
- **DNC-AUTH-3** `ValidateLifetime`, `ValidateIssuer`, `ValidateAudience`, `ValidateIssuerSigningKey` ALL true. Any false = bypass.
- **DNC-AUTH-4** Identity uses Argon2/PBKDF2 (default PBKDF2 acceptable; verify iteration count).
- **DNC-AUTH-5** Cookie authentication: `SecurePolicy = CookieSecurePolicy.Always`, `HttpOnly = true`, `SameSite = SameSiteMode.Lax`.

#### Authorization

- **DNC-AZ-1** `[Authorize]` on controllers requiring auth. Or global filter:
  ```csharp
  builder.Services.AddControllers(opts => {
      var policy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
      opts.Filters.Add(new AuthorizeFilter(policy));
  });
  ```
  Public actions then need `[AllowAnonymous]`.
- **DNC-AZ-2** Policy-based authz (`[Authorize(Policy = "AdminOnly")]`) with handlers checking specific claims.
- **DNC-AZ-3** Resource-based authz via `IAuthorizationService.AuthorizeAsync(user, resource, policy)` for per-instance checks.
- **DNC-AZ-4** No `[Authorize]` missing from sensitive endpoints — common bug class.

#### Antiforgery (CSRF)

- **DNC-CSRF-1** `[ValidateAntiForgeryToken]` on Razor Pages POST handlers, or global filter for MVC.
- **DNC-CSRF-2** API endpoints using cookie auth: CSRF protection still required. Use `[ValidateAntiForgeryToken]` or send via header.
- **DNC-CSRF-3** Bearer token APIs (no cookie auth): CSRF not needed.

#### Model binding — overposting

- **DNC-MB-1** Action methods accept dedicated DTOs/ViewModels, NOT entity classes:
  ```csharp
  // BAD — User has IsAdmin property, attacker sets it
  public IActionResult Create([FromBody] User user) { ... }
  
  // GOOD
  public IActionResult Create([FromBody] CreateUserDto dto) { ... }
  ```
- **DNC-MB-2** `[Bind("Name,Email")]` attribute used to limit binding when entity must be used.
- **DNC-MB-3** Validation attributes (`[Required]`, `[StringLength]`, `[RegularExpression]`) on DTOs.

#### SQL injection (EF Core)

- **DNC-SQL-1** `FromSqlRaw($"SELECT * FROM Users WHERE Id = {id}")` is injection. Use:
  ```csharp
  // GOOD
  context.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Id = {id}");
  // OR
  context.Users.FromSqlRaw("SELECT * FROM Users WHERE Id = {0}", id);
  ```
- **DNC-SQL-2** `ExecuteSqlRaw` similarly — interpolated or parameterized only.
- **DNC-SQL-3** EF Core LINQ queries parameterize automatically — safe.

#### CORS

- **DNC-COR-1** CORS policy defines specific origins, not `AllowAnyOrigin` for credentialed APIs.
- **DNC-COR-2** `AllowCredentials()` only with specific origins (combined with `AllowAnyOrigin` is rejected by spec).

#### Configuration / secrets

- **DNC-CFG-1** `appsettings.json` and `appsettings.Development.json` don't contain real production secrets.
- **DNC-CFG-2** Production secrets via environment variables, Azure Key Vault, AWS Secrets Manager — accessed through `IConfiguration`.
- **DNC-CFG-3** User Secrets used for local dev (`dotnet user-secrets set ...`) — never in production.
- **DNC-CFG-4** Connection strings without password baked in (use integrated auth or env vars).

#### Data Protection

ASP.NET Core's Data Protection provides keys for cookies, antiforgery tokens, etc.

- **DNC-DP-1** Data Protection keys persisted to durable storage (Azure Blob, Redis, filesystem) — not in-memory if you have multiple instances.
- **DNC-DP-2** Keys encrypted at rest if filesystem-based.
- **DNC-DP-3** `SetApplicationName` set if multiple apps share the key ring.

#### File uploads

- **DNC-UP-1** `IFormFile` size limited via `RequestSizeLimit` attribute or `Kestrel.Limits.MaxRequestBodySize`.
- **DNC-UP-2** Content type validated via byte sniffing (use a library like `SixLabors.ImageSharp` for images), not trusted from header.
- **DNC-UP-3** Filenames sanitized; use UUIDs.

#### Logging

- **DNC-LOG-1** Sensitive parameter logging disabled; EF Core `EnableSensitiveDataLogging` NEVER true in production.
- **DNC-LOG-2** `[LogProperties]` on sensitive DTOs excludes password/secret fields.

#### Exception handling

- **DNC-EX-1** Production uses `app.UseExceptionHandler("/error")` (not `UseDeveloperExceptionPage`).
- **DNC-EX-2** Custom error response doesn't include stack traces.
- **DNC-EX-3** `app.UseStatusCodePages` configured if custom 404/500 pages needed.

#### Headers

- **DNC-HDR-1** `app.UseSecurityHeaders(...)` (NWebsec or similar) OR explicit middleware setting CSP, X-Content-Type-Options, X-Frame-Options.
- **DNC-HDR-2** `Server` header removed (Kestrel: `AddServerHeader = false`).

#### Minimal API specifics

- **DNC-MA-1** Minimal API endpoints use `.RequireAuthorization()` for protected routes.
- **DNC-MA-2** Endpoint filters for cross-cutting validation.

#### Razor Pages / MVC views

- **DNC-RAZ-1** Razor auto-encodes `@Model.Foo`. `@Html.Raw(...)` and `Html.Raw(Model.Foo)` skip encoding — review usages.
- **DNC-RAZ-2** No `@(Model.Bar)` patterns rendering unencoded HTML from user input.

#### Dependencies

- **DNC-DEP-1** Target framework current (.NET 8 LTS or .NET 9 STS).
- **DNC-DEP-2** `dotnet list package --vulnerable` clean.
- **DNC-DEP-3** Old Newtonsoft.Json JSON serializer with TypeNameHandling.Auto / All on untrusted input = RCE. Use System.Text.Json or restrict TypeNameHandling.

### Phase 4: Triage

Critical: `[Authorize]` missing on admin endpoints; JWT validation with any of the 4 validates false; FromSqlRaw with string interpolation; ASP.NET Core version with known CVE.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `DNC-`.
