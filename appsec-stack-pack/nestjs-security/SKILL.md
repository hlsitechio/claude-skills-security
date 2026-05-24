---
name: nestjs-security
description: Security audit for NestJS applications including Guards (AuthGuard, RolesGuard), Interceptors, Pipes (ValidationPipe), custom decorators, module structure, dependency injection scoping, GraphQL/REST integration, microservices (TCP, Redis, Kafka transports), and NestJS-specific patterns. Use this skill whenever the user mentions NestJS, @nestjs/common, @nestjs/core, Guards, Interceptors, ValidationPipe, NestFactory, @Injectable, @Module, @Controller, @UseGuards, @UseInterceptors, or asks "audit my NestJS app", "NestJS guards safe", "ValidationPipe security". Trigger when the codebase contains `@nestjs/core` or `@nestjs/common` in package.json.
---

# NestJS Security Audit

Audit NestJS applications. NestJS sits on top of Express or Fastify; specific patterns (decorators, DI, modules) introduce their own audit surface.

## When this skill applies

- Reviewing Guards and authorization logic
- Auditing ValidationPipe configuration
- Reviewing Interceptors for unsafe transformations
- Checking module structure and provider scoping
- Reviewing GraphQL or REST controllers built on Nest

## Workflow

Follow `../_shared/audit-workflow.md`. Companion: `nodejs-express-security` for underlying middleware concerns.

### Phase 1: Stack detection

```bash
grep -E '"@nestjs/(core|common|platform-express|platform-fastify)":' package.json
find . -name 'main.ts' -path '*src*' -not -path '*/node_modules/*'
find . -name 'nest-cli.json'
```

Detect: platform (Express vs Fastify), use of GraphQL (`@nestjs/graphql`), use of microservices (`@nestjs/microservices`).

### Phase 2: Inventory

```bash
# Controllers and routes
grep -rn '@Controller\|@Get\|@Post\|@Put\|@Delete' src/ | head -50

# Guards
grep -rn '@UseGuards\|implements CanActivate' src/

# Interceptors
grep -rn '@UseInterceptors\|implements NestInterceptor' src/

# Pipes
grep -rn 'useGlobalPipes\|@UsePipes\|ValidationPipe' src/

# CORS
grep -rn 'enableCors\|cors:' src/main.ts src/app.module.ts 2>/dev/null

# Microservices
grep -rn 'createMicroservice\|@MessagePattern\|@EventPattern' src/
```

### Phase 3: Detection — the checks

#### Guards

Guards implement `CanActivate`. They run before route handlers.

- **NST-GUARD-1** Every endpoint that should be authenticated has `@UseGuards(AuthGuard)` or global app-level guard.
- **NST-GUARD-2** Public endpoints explicitly marked (e.g., `@Public()` decorator), and the global guard checks for that decorator. Don't rely on "remembering" to apply guards.
  ```ts
  // GOOD pattern — global guard + opt-out
  app.useGlobalGuards(new AuthGuard(reflector));
  
  // controllers/auth.controller.ts
  @Public()
  @Post('login')
  login(@Body() dto: LoginDto) { ... }
  ```
- **NST-GUARD-3** Role-based guards check the user's role against required roles via decorator metadata:
  ```ts
  @Roles('admin')
  @UseGuards(RolesGuard)
  ```
  Verify `RolesGuard` actually reads `Roles` metadata and compares.
- **NST-GUARD-4** Guards don't short-circuit silently — return `false` or throw; never resolve to `true` on unexpected input.
- **NST-GUARD-5** Per-resource authz (ownership checks) NOT done in guards (guards don't have easy access to mutated body); done in service layer.

#### ValidationPipe

- **NST-PIPE-1** `app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }))` applied globally.
  - `whitelist: true` — strips properties not declared on the DTO. Prevents mass assignment.
  - `forbidNonWhitelisted: true` — REJECTS requests with extra properties (stricter).
  - `transform: true` — converts payload to DTO class instance, applying transforms.
- **NST-PIPE-2** DTOs use `class-validator` decorators (`@IsString`, `@IsEmail`, `@Length`, etc.).
- **NST-PIPE-3** Sensitive fields not exposed via `@Expose()` from `class-transformer` on response DTOs (use `@Exclude()` for password hashes etc., or use serializer interceptor).
- **NST-PIPE-4** Nested DTOs use `@Type(() => Nested)` for transform to work recursively.

```ts
// dto/create-user.dto.ts
import { IsEmail, IsString, Length, IsOptional } from 'class-validator';

export class CreateUserDto {
  @IsEmail()
  email!: string;
  
  @IsString()
  @Length(8, 128)
  password!: string;
  
  @IsString()
  @Length(1, 50)
  displayName!: string;
  
  // role is intentionally not on the DTO — set by server
}
```

#### Interceptors

- **NST-INT-1** Logging interceptors don't log full request body (password, secrets).
- **NST-INT-2** Serialization interceptor strips sensitive response fields:
  ```ts
  @UseInterceptors(ClassSerializerInterceptor)
  ```
  Combined with `@Exclude()` on the entity, ensures secrets don't ship.
- **NST-INT-3** Caching interceptors keyed by user/tenant when caching per-user data (otherwise cross-user cache hits).

#### Exception filters

- **NST-EX-1** Global exception filter in production hides stack traces and internal error details.
- **NST-EX-2** Specific HTTP exceptions (`UnauthorizedException`, `ForbiddenException`, `NotFoundException`) used appropriately — don't return 500 for client errors.
- **NST-EX-3** Database error details (constraint names, table names) not bubbled to clients.

#### Middleware

NestJS supports both Express middleware and Nest-style middleware. Order matters:

- **NST-MW-1** Security middleware (`helmet`, `cors`) configured in `main.ts` before `app.listen()`.
- **NST-MW-2** Rate limiting via `@nestjs/throttler` or `express-rate-limit`. Throttler applied globally or per-controller.
- **NST-MW-3** `app.enableCors(...)` with specific options (not `enableCors()` with default `*`).

#### Modules and DI scoping

- **NST-DI-1** Request-scoped providers used for per-request state (e.g., logger with request ID). Don't put per-request data in singleton-scoped providers.
- **NST-DI-2** Sensitive services (e.g., AuthService) only exported from modules that should access them; don't `exports: [AuthService]` from auth module to public modules without need.
- **NST-DI-3** `@Global()` modules limited to truly global concerns.

#### Authentication strategies (Passport)

If using `@nestjs/passport`:

- **NST-AUTH-1** JWT strategy validates signature, expiry, issuer, audience. See `saas-security-pack/saas-code-security-review/references/jwt-validation.md`.
- **NST-AUTH-2** Local strategy compares password with `bcrypt.compare` (constant-time); don't use `===`.
- **NST-AUTH-3** Session-based: connect session middleware before Passport.
- **NST-AUTH-4** Refresh token rotation implemented (issue new RT on use, revoke old).

#### GraphQL (if using @nestjs/graphql)

- **NST-GQL-1** Apollo Driver config: `introspection` disabled in production, `playground` disabled.
- **NST-GQL-2** Resolvers use `@UseGuards(...)` for auth.
- **NST-GQL-3** See `graphql-security` skill for depth/complexity, field-level auth.

#### Microservices (TCP, Redis, Kafka, gRPC transports)

- **NST-MS-1** Microservice transport not exposed publicly. TCP transport with default settings binds to all interfaces.
- **NST-MS-2** Message handlers (`@MessagePattern`) validate inputs — they're effectively RPC endpoints without HTTP middleware.
- **NST-MS-3** Inter-service auth: signed messages or mTLS between services; don't rely on network-only isolation.

#### File uploads

- **NST-UP-1** `@nestjs/platform-express` Multer config has size and count limits.
- **NST-UP-2** Validate file type by magic bytes (see `nodejs-express-security`).

#### Config module

- **NST-CFG-1** `ConfigModule` with `validate` function ensures required env vars present at startup.
- **NST-CFG-2** Secrets accessed via `ConfigService.get('SECRET')` — not from `process.env` directly (so test/runtime config swapping works).
- **NST-CFG-3** `validationSchema` (Joi or Zod) requires specific env shape; fails fast on misconfiguration.

#### Dependencies

- **NST-DEP-1** NestJS versions current (10.x or 11.x).
- **NST-DEP-2** Companion: `nodejs-express-security` for underlying Express/Fastify checks.

### Phase 4: Triage

Critical: missing global ValidationPipe with whitelist; sensitive route without `@UseGuards`; CORS open with credentials; microservice handlers with no input validation.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `NST-`.
