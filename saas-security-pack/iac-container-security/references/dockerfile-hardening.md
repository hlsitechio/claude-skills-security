# Dockerfile Hardening Reference

Load this when reviewing or writing Dockerfiles for security.

## The hardened template

```dockerfile
# syntax=docker/dockerfile:1.7
# Build stage
FROM node:20.11.1-bookworm-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --ignore-scripts --omit=dev
COPY . .
RUN npm run build

# Runtime stage
FROM gcr.io/distroless/nodejs20-debian12:nonroot AS runtime
WORKDIR /app
COPY --from=build --chown=nonroot:nonroot /app/dist /app/dist
COPY --from=build --chown=nonroot:nonroot /app/node_modules /app/node_modules
COPY --from=build --chown=nonroot:nonroot /app/package.json /app/package.json
USER nonroot
EXPOSE 8080
ENV NODE_ENV=production
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8080/healthz').then(r=>r.ok?0:process.exit(1)).catch(()=>process.exit(1))"]
CMD ["dist/server.js"]
```

What each line does for security:
- `node:20.11.1-bookworm-slim` — specific patch version, slim variant (fewer CVEs).
- Multi-stage — build tools (npm, gcc, headers) stay in build stage, not in runtime image.
- `npm ci --ignore-scripts` — no lifecycle script execution during install.
- Distroless runtime — no shell, no package manager, ~50MB vs ~900MB for full node image.
- `USER nonroot` — process doesn't run as UID 0; container escape is much harder.
- `--chown` on COPY — owner is the runtime user, not root.
- `HEALTHCHECK` — orchestrator can detect unhealthy containers.

## What to flag in an audit

### Flag 1 — Floating tags

```dockerfile
FROM node:latest          # ⚠ pulls whatever is latest at build time
FROM python:3            # ⚠ minor version drifts
FROM ubuntu              # ⚠ rolling
```

Fix: pin to a specific version (`node:20.11.1-bookworm-slim`). For maximum safety, pin by digest: `FROM node@sha256:abc...`.

### Flag 2 — Running as root

```dockerfile
FROM alpine:3.19
COPY app /app
CMD ["/app"]
# Runs as root (UID 0)
```

Container running as root is a privilege escalation vector if there's a kernel CVE or misconfigured cgroup. Always declare a non-root user:

```dockerfile
FROM alpine:3.19
RUN adduser -D -u 1000 appuser
COPY --chown=appuser:appuser app /app
USER appuser
CMD ["/app"]
```

### Flag 3 — Secrets in image layers

```dockerfile
ENV DATABASE_URL=postgres://user:p4ssw0rd@host/db    # ⚠ baked in layer
COPY .env /app/.env                                   # ⚠ secret in layer
ARG AWS_SECRET_ACCESS_KEY                             # ⚠ build-arg in layer
RUN echo "$SLACK_TOKEN" > /tmp/token                  # ⚠ visible in history
```

Even if a later layer removes the file, the secret is in the layer history. Anyone with the image can `docker history --no-trunc <image>` and extract.

Fixes:
- Runtime config from env at runtime, not from image layer.
- Build-time secrets via `--secret` mount (BuildKit):
  ```dockerfile
  # syntax=docker/dockerfile:1.7
  RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci
  ```
- For static assets that need to bundle a secret (rare, usually a bad sign), reconsider the design.

### Flag 4 — Single-stage with build tools

```dockerfile
FROM node:20-bookworm    # full image: ~1GB, includes build tools, shell, package manager
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build
CMD ["node", "dist/server.js"]
```

`gcc`, `apt`, `bash`, and dozens of CVE-prone packages travel into production. Multi-stage cuts that to just the runtime.

### Flag 5 — Using `ADD` for URLs

```dockerfile
ADD https://example.com/some-binary /usr/local/bin/   # ⚠ no integrity check
```

`ADD` downloads without verification. If you must fetch at build time:

```dockerfile
ARG TOOL_VERSION=1.2.3
ARG TOOL_SHA256=abc123...
RUN curl -fsSL https://example.com/tool-${TOOL_VERSION}.tar.gz -o /tmp/tool.tar.gz \
  && echo "${TOOL_SHA256}  /tmp/tool.tar.gz" | sha256sum -c \
  && tar -xzf /tmp/tool.tar.gz -C /usr/local \
  && rm /tmp/tool.tar.gz
```

Better: fetch in build stage with verification; copy to runtime as a verified artifact.

### Flag 6 — `apt-get install` without `--no-install-recommends`

```dockerfile
RUN apt-get update && apt-get install -y curl ca-certificates && rm -rf /var/lib/apt/lists/*
# ⚠ pulls in dozens of recommended packages, bloating image and CVE surface
```

Fix:

```dockerfile
RUN apt-get update \
  && apt-get install -y --no-install-recommends curl ca-certificates \
  && rm -rf /var/lib/apt/lists/*
```

### Flag 7 — No `.dockerignore`

Without `.dockerignore`, `COPY . .` includes:
- `.git/` — leaks commit history, branch names, possibly secrets.
- `.env` — likely the most catastrophic.
- `node_modules/` — bloats image, possibly different platform.
- `tests/`, `docs/` — bloats.
- `.vscode/`, `.idea/` — leaks dev config.

Minimum `.dockerignore`:

```
.git
.gitignore
.env
.env.*
!.env.example
node_modules
npm-debug.log*
.DS_Store
*.swp
.vscode/
.idea/
coverage/
tests/
docs/
README.md
*.md
Dockerfile*
.dockerignore
.github/
```

### Flag 8 — `latest` tag in CMD/ENTRYPOINT references

```dockerfile
FROM mysql:latest
CMD ["docker-entrypoint.sh", "mysqld"]
```

The image is the moving part. Pin it; the entrypoint reference doesn't matter.

### Flag 9 — No HEALTHCHECK

Without HEALTHCHECK, orchestrators can't detect a stuck process. Always define one (for k8s, the equivalent is `livenessProbe` / `readinessProbe` in the manifest).

### Flag 10 — Setuid binaries left in image

A common bypass for non-root: a setuid binary in the image lets the unprivileged user gain root. Strip setuid:

```dockerfile
RUN find / -perm /4000 -type f 2>/dev/null | xargs -r chmod u-s
```

Or use distroless `:nonroot` which already does this.

## Image scanning

Run in CI:

```yaml
- name: Scan image with Trivy
  uses: aquasecurity/trivy-action@<sha>
  with:
    image-ref: ghcr.io/${{ github.repository }}:${{ github.sha }}
    severity: HIGH,CRITICAL
    exit-code: 1                  # fail the build on findings
    ignore-unfixed: true          # don't fail on unfixable CVEs
```

For Docker Hub or other registries, similar with `docker scout cves` or Snyk.

### Triaging CVEs

Not every CVE is exploitable in your image's context:
- A CVE in a library your app doesn't actually use is low impact.
- A CVE that requires local access in a container with no shell is much less serious.
- A "won't fix" CVE (upstream considers it not exploitable in their context) may still need explicit acceptance.

Use `.trivyignore` for accepted CVEs with comments explaining why.

## Base image strategies

| Base | Size | Surface | Use when |
|------|------|---------|----------|
| `gcr.io/distroless/<lang>:nonroot` | ~20-80MB | minimal, no shell | Most production workloads |
| `alpine` | ~5MB + lang | musl libc (some incompat); shell | When you need shell or musl is fine |
| `chainguard.dev/<lang>` | ~30-60MB | distroless-like, with security focus | Same as distroless, often more current |
| `cgr.dev/chainguard/wolfi-base` | ~10MB | minimal Linux with apk | When you need apk install at build time |
| `ubuntu:22.04` / `debian:12-slim` | ~50-100MB | full distro | Legacy apps requiring system libs |
| `scratch` | 0 | empty | Static Go binaries |

For Go: `FROM scratch` with a static binary is unbeatable on size and surface. Just add CA certs:

```dockerfile
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /app /app
USER 65534:65534
ENTRYPOINT ["/app"]
```

## Signing and provenance

Sign images at build time with Cosign:

```yaml
- uses: sigstore/cosign-installer@<sha>
- run: |
    cosign sign --yes ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
```

Add SLSA provenance:

```yaml
- uses: actions/attest-build-provenance@<sha>
  with:
    subject-path: 'image-digest:${{ steps.build.outputs.digest }}'
```

See `github-supply-chain/references/sbom-generation.md` for the full SBOM + provenance pattern.

## Audit checklist

For each Dockerfile:

1. Pinned base image (version + ideally digest).
2. Multi-stage build (build tools not in runtime).
3. Non-root user declared and used.
4. No secrets in layers.
5. `.dockerignore` excludes git, env, secrets, dev artifacts.
6. Distroless or minimal base.
7. `--no-install-recommends` on apt; equivalent on apk.
8. No `ADD` for URLs without checksum verification.
9. HEALTHCHECK declared (or k8s probes in manifest).
10. CI scans image with Trivy / Snyk / Scout; build fails on High/Critical.
11. Image signed at build; provenance attested.
