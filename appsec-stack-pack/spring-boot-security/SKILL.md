---
name: spring-boot-security
description: Security audit for Spring Boot Java/Kotlin applications including Spring Security configuration, @PreAuthorize/@Secured, JPA queries (@Query, JPQL injection), CSRF setup, CORS, actuator endpoints exposure, application.yml secrets, Jackson deserialization, and Spring-specific CVE awareness (Spring4Shell). Use this skill whenever the user mentions Spring Boot, Spring Security, @PreAuthorize, JpaRepository, application.yml/properties, actuator, @SpringBootApplication, or asks "audit my Spring app", "Spring Boot security review". Trigger when the codebase contains `pom.xml` or `build.gradle` with `spring-boot-starter`, or Java/Kotlin files with `@SpringBootApplication`.
---

# Spring Boot Security Audit

Audit Spring Boot applications (Java and Kotlin, 2.7+ and 3.x).

## When this skill applies

- Reviewing Spring Security configuration classes
- Auditing JPA repository methods and queries
- Reviewing controller-level authorization annotations
- Checking actuator endpoint exposure
- Reviewing application.yml / application.properties for secrets

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection

```bash
grep -E 'spring-boot-starter' pom.xml build.gradle build.gradle.kts 2>/dev/null
grep -E 'org.springframework' pom.xml 2>/dev/null | head
```

### Phase 2: Inventory

```bash
# Security configuration
grep -rn 'SecurityFilterChain\|WebSecurityConfigurerAdapter\|EnableWebSecurity\|EnableMethodSecurity' src/ --include='*.java' --include='*.kt'

# Controllers
grep -rn '@RestController\|@Controller\|@RequestMapping\|@GetMapping\|@PostMapping' src/ --include='*.java' --include='*.kt' | head

# Authorization annotations
grep -rn '@PreAuthorize\|@PostAuthorize\|@Secured\|@RolesAllowed' src/ --include='*.java' --include='*.kt'

# Custom queries
grep -rn '@Query\|@NativeQuery\|createNativeQuery\|createQuery' src/ --include='*.java' --include='*.kt'

# Config files
ls src/main/resources/application*.yml src/main/resources/application*.properties 2>/dev/null
```

### Phase 3: Detection — the checks

#### Spring Security configuration

Modern Spring Security 6 uses `SecurityFilterChain` bean. Older used `WebSecurityConfigurerAdapter` (removed in 6).

- **SPR-SC-1** A `SecurityFilterChain` bean explicitly configured. Don't rely on Spring defaults (they permit-all in older versions).
- **SPR-SC-2** Default deny: routes not matched fall through to `.anyRequest().authenticated()` or `.denyAll()`.
- **SPR-SC-3** Public endpoints explicitly allowlisted; everything else requires auth.

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/login", "/signup", "/health").permitAll()
            .requestMatchers("/admin/**").hasRole("ADMIN")
            .anyRequest().authenticated())
        .csrf(csrf -> csrf
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
        .headers(headers -> headers
            .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'")))
        .build();
}
```

#### Authentication

- **SPR-AUTH-1** Password encoder is BCrypt, Argon2, or Pbkdf2 — not NoOp.
- **SPR-AUTH-2** `UserDetailsService` returns null-safe results; doesn't leak existence via timing or different error messages.
- **SPR-AUTH-3** JWT validation: see `saas-security-pack/saas-code-security-review/references/jwt-validation.md`. Spring Security OAuth2 Resource Server is the well-trodden path.
- **SPR-AUTH-4** Session fixation protection enabled (default in Spring Security; verify not disabled).

#### Authorization

- **SPR-AZ-1** `@EnableMethodSecurity` on configuration class to enable `@PreAuthorize`.
- **SPR-AZ-2** Service methods that mutate user data have `@PreAuthorize("hasRole('USER') and #userId == authentication.principal.id")`.
- **SPR-AZ-3** Controllers use `@PreAuthorize` OR url-based config — not both inconsistently.
- **SPR-AZ-4** `@PreFilter` / `@PostFilter` on collection returns to enforce per-element authz.

#### CSRF

- **SPR-CSRF-1** CSRF enabled by default. If disabled (`.csrf(csrf -> csrf.disable())`), endpoints must be stateless (token auth, no cookie sessions).
- **SPR-CSRF-2** REST APIs using JWT in headers can disable CSRF. Cookie-based REST APIs cannot.
- **SPR-CSRF-3** `CookieCsrfTokenRepository.withHttpOnlyFalse()` — the CSRF cookie must be JS-readable for SPAs to send the header; this is correct, not a finding.

#### CORS

- **SPR-COR-1** CORS configured via `CorsConfigurationSource` bean with specific origins, methods, headers.
- **SPR-COR-2** `setAllowCredentials(true)` only with specific origins.

#### SQL injection (JPA, JdbcTemplate)

- **SPR-SQL-1** `@Query` with `?1` or named parameters `:userId` is parameterized.
- **SPR-SQL-2** String concatenation in JPQL/native queries is injection:
  ```java
  // BAD
  @Query(value = "SELECT * FROM users WHERE name = '" + name + "'", nativeQuery = true)
  
  // GOOD
  @Query(value = "SELECT * FROM users WHERE name = :name", nativeQuery = true)
  User findByName(@Param("name") String name);
  ```
- **SPR-SQL-3** `JdbcTemplate.queryForObject(sql, ...)` uses placeholders; not `String.format`.
- **SPR-SQL-4** Criteria API and Specification queries safe; dynamic identifiers need allowlist.

#### Jackson deserialization (Spring4Shell-class)

- **SPR-JKS-1** Don't deserialize untrusted JSON into polymorphic types (`@JsonTypeInfo` with default typing). CVE-2017-7525, Spring4Shell (CVE-2022-22965) class.
- **SPR-JKS-2** Spring Boot 2.7+ / 3.x patched against the original Spring4Shell vector, but custom Binder configurations may reintroduce — audit any custom `WebDataBinder` config.
- **SPR-JKS-3** `@RestController` methods accepting `Object` or generic types are dangerous; use specific DTOs.

#### Mass assignment via `@ModelAttribute`

- **SPR-MA-1** Controller methods accepting `@ModelAttribute User user` bind every field. Use DTOs separate from entities:
  ```java
  @PostMapping("/users")
  public User create(@RequestBody @Valid CreateUserDto dto) {
      // build entity from DTO, set role server-side
  }
  ```
- **SPR-MA-2** `WebDataBinder` `setAllowedFields(...)` configured if using `@ModelAttribute` on entities.

#### Actuator endpoints

Spring Boot Actuator exposes runtime info. Production exposure can leak sensitive data.

- **SPR-ACT-1** `management.endpoints.web.exposure.include` lists only safe endpoints (`health`, `info`). NOT `*` in production.
- **SPR-ACT-2** Sensitive endpoints (`heapdump`, `env`, `configprops`, `loggers`, `mappings`, `threaddump`) disabled or auth-gated.
- **SPR-ACT-3** `/actuator/health` includes only basic status in production (`management.endpoint.health.show-details: when-authorized`).
- **SPR-ACT-4** Actuator on separate management port not reachable from public internet.

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info
  endpoint:
    health:
      show-details: when-authorized
  server:
    port: 8081  # internal-only port
```

#### Configuration / secrets

- **SPR-CFG-1** Secrets in `application.yml` use placeholders pulled from env or Vault:
  ```yaml
  spring:
    datasource:
      password: ${DB_PASSWORD}
  ```
- **SPR-CFG-2** No committed `application-prod.yml` with real secrets.
- **SPR-CFG-3** Profiles (`application-prod.yml`, `application-dev.yml`) loaded based on `SPRING_PROFILES_ACTIVE`; production profile sets secure defaults.

#### File uploads

- **SPR-UP-1** `spring.servlet.multipart.max-file-size` and `max-request-size` set.
- **SPR-UP-2** Content type validated by magic bytes (Apache Tika, etc.).

#### Headers

- **SPR-HDR-1** Spring Security headers defaults reasonable; HSTS, X-Content-Type-Options, X-Frame-Options enabled.
- **SPR-HDR-2** CSP configured via `.headers(h -> h.contentSecurityPolicy(...))`.

#### Logging

- **SPR-LOG-1** `logging.level` not DEBUG/TRACE in production for security-relevant packages (`org.springframework.security`).
- **SPR-LOG-2** Request body logging filters skip sensitive paths (`/login`, `/api/auth`).

#### Dependencies

- **SPR-DEP-1** Spring Boot version on supported line (3.x preferred; 2.7 LTS until end of OSS support).
- **SPR-DEP-2** `mvn dependency-check:check` (OWASP Dependency-Check) or `gradle dependencyCheckAnalyze` clean.
- **SPR-DEP-3** Spring Cloud, Spring Data versions compatible with Spring Boot.

### Phase 4: Triage

Critical: actuator `*` exposed; CSRF disabled with cookie sessions; raw SQL with String concatenation; Spring Boot version with unpatched RCE.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `SPR-`.
