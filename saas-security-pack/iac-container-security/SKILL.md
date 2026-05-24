---
name: iac-container-security
description: "Audit infrastructure-as-code and container security including Terraform/OpenTofu/Pulumi configurations, Dockerfile hardening, Kubernetes manifests, base image hygiene, container scanning, secrets in IaC, IAM policies, network exposure, and runtime security context. Multi-cloud (AWS, GCP, Azure). Use this skill whenever the user asks about Terraform security, tfsec, Checkov, Trivy, Dockerfile hardening, distroless images, k8s securityContext, network policies, IAM least privilege, IaC secret scanning, or 'audit my infrastructure'. Trigger on phrases like 'scan my Dockerfile', 'review my Terraform', 'audit my k8s manifests', 'harden my containers', 'IaC security', 'base image hygiene', 'container CVEs', 'trivy scan'. Use this even when only one IaC layer is mentioned."
---

# IaC and Container Security Audit

Audit infrastructure-as-code repositories and container images for security issues that compromise deployments. Defensive find-and-fix.

## When this skill applies

- Reviewing Terraform / OpenTofu / Pulumi / CloudFormation / ARM templates
- Hardening Dockerfile or reviewing built container images
- Reviewing Kubernetes manifests (Deployments, Services, NetworkPolicies, RBAC)
- Auditing IAM policies for least-privilege violations
- Interpreting output from tfsec, Checkov, Trivy, kubesec, kube-bench
- Reviewing cloud configuration drift (actual cloud state vs IaC)

Use other skills for: workflow/CI security (`github-supply-chain`), app-layer concerns (`saas-code-security-review`, `saas-api-security`).

## Workflow

Follow `../_shared/audit-workflow.md`. IaC-specific notes below.

### Phase 1: Scope confirmation

- Which IaC tools (Terraform, Pulumi, CDK, CloudFormation, Bicep, Helm)?
- Which container runtime (Docker, containerd, ECS, k8s, Cloud Run, App Runner)?
- Which cloud(s)?
- Is the IaC the source of truth, or is config drift expected?

### Phase 2: Inventory

```bash
# IaC files
find . -name '*.tf' -o -name '*.tfvars' \
  -o -name 'Pulumi.yaml' -o -name '*.bicep' \
  -o -name 'cloudformation*.yml' -o -name 'cloudformation*.yaml' \
  -o -name 'Dockerfile*' -o -name 'docker-compose*.yml' \
  -o -path '*/k8s/*.yaml' -o -path '*/manifests/*.yaml' \
  | grep -v node_modules

# Run security scanners (read-only)
trivy fs --severity HIGH,CRITICAL .
checkov -d . --quiet --output cli
tfsec . --soft-fail
docker scout cves --only-severity high,critical local://your-image:tag
```

### Phase 3: Detection — the checks

#### Dockerfile — see `references/dockerfile-hardening.md`

- **IACS-DF-1** Pinned base image (`FROM node:20.11.1-alpine` not `FROM node:latest`).
- **IACS-DF-2** Non-root user (`USER appuser`) declared and used at runtime.
- **IACS-DF-3** No secrets baked into image layers (`ENV` with credential, `COPY .env`).
- **IACS-DF-4** No unnecessary tools (curl, wget, git, build tools) in production stage.
- **IACS-DF-5** Multi-stage build separating build environment from runtime.
- **IACS-DF-6** `HEALTHCHECK` defined.
- **IACS-DF-7** `.dockerignore` excluding `.git`, `.env`, `node_modules` (avoids bloat AND secret leakage).
- **IACS-DF-8** Distroless or minimal base image (`gcr.io/distroless/`, `alpine`, `chainguard`).
- **IACS-DF-9** No `ADD` for URLs (use `RUN curl` with verification, or better, no fetches at all).
- **IACS-DF-10** Image scanned for CVEs in CI; build fails on High/Critical without exception.

#### Kubernetes manifests — see `references/k8s-hardening.md`

- **IACS-K8S-1** `runAsNonRoot: true` and `runAsUser: <uid>` in pod/container securityContext.
- **IACS-K8S-2** `readOnlyRootFilesystem: true` (with emptyDir for writable paths if needed).
- **IACS-K8S-3** `allowPrivilegeEscalation: false`.
- **IACS-K8S-4** `capabilities: { drop: [ALL] }` and add only what's needed.
- **IACS-K8S-5** No `privileged: true` (or documented justification).
- **IACS-K8S-6** `hostNetwork`, `hostPID`, `hostIPC` all false.
- **IACS-K8S-7** Resource requests AND limits set on every container.
- **IACS-K8S-8** NetworkPolicy default-deny in every namespace; specific allow rules.
- **IACS-K8S-9** ServiceAccount per workload (not shared `default` SA).
- **IACS-K8S-10** Pod Security Admission level `restricted` for application namespaces.
- **IACS-K8S-11** No secrets in `env` from literal values; use `valueFrom: secretKeyRef`.
- **IACS-K8S-12** Image pull from a private registry with image digest pinning (`image: registry/foo@sha256:...`).

#### Terraform / OpenTofu

- **IACS-TF-1** State stored in remote backend with encryption + state locking (S3 + DynamoDB, GCS, Azure storage).
- **IACS-TF-2** State backend access restricted to deployer role/team.
- **IACS-TF-3** No secrets in `.tf` or `.tfvars` committed to git. Use Vault / SOPS / cloud secret manager.
- **IACS-TF-4** Provider versions pinned in `required_providers`.
- **IACS-TF-5** Modules sourced from trusted registries with version pins.
- **IACS-TF-6** `terraform plan` reviewed in CI before apply; manual approval for production apply.
- **IACS-TF-7** Drift detection runs (e.g., scheduled `terraform plan` alert).

#### Common cloud resource issues

**Storage (S3/GCS/Azure Blob):**
- **IACS-STOR-1** No `Public Access = ON` without explicit business need.
- **IACS-STOR-2** Bucket policies don't allow `Principal: "*"` for sensitive buckets.
- **IACS-STOR-3** Server-side encryption enabled.
- **IACS-STOR-4** Versioning enabled on critical buckets.
- **IACS-STOR-5** Lifecycle rules archive/delete old data.
- **IACS-STOR-6** Logging to a separate (audit) bucket.

**Compute (EC2/GCE/Azure VM):**
- **IACS-COMP-1** No SSH 0.0.0.0/0 in security group / firewall.
- **IACS-COMP-2** IMDSv2 enforced (AWS).
- **IACS-COMP-3** Instance role scoped, not full admin.
- **IACS-COMP-4** Disks encrypted.
- **IACS-COMP-5** Public IP only when required.

**Networking:**
- **IACS-NET-1** Default VPC/subnets not used for production.
- **IACS-NET-2** Security groups / firewall rules scoped (no `0.0.0.0/0` on internal services).
- **IACS-NET-3** Subnets logically separated (public/private/data).
- **IACS-NET-4** Egress controlled (especially for compute that processes user data).
- **IACS-NET-5** VPC flow logs enabled.

**Databases (RDS/CloudSQL/Azure DB):**
- **IACS-DB-1** Not publicly accessible.
- **IACS-DB-2** Encryption at rest and in transit.
- **IACS-DB-3** Backup retention ≥ 7 days.
- **IACS-DB-4** Multi-AZ / replica for production.
- **IACS-DB-5** Master password from secret manager.
- **IACS-DB-6** Slow query / audit logging where supported.

**IAM:**
- **IACS-IAM-1** No `*:*` policies on production roles.
- **IACS-IAM-2** No `Principal: "*"` on resource policies without explicit `aws:SourceArn`/equivalent constraint.
- **IACS-IAM-3** Roles per-workload, not shared.
- **IACS-IAM-4** No long-lived access keys (use roles/OIDC).
- **IACS-IAM-5** MFA required for sensitive operations.
- **IACS-IAM-6** Permission boundaries on roles delegated to applications.

**Secrets / KMS:**
- **IACS-SEC-1** All secrets in a managed secret store (Secrets Manager, GCP Secret Manager, Azure Key Vault, Vault).
- **IACS-SEC-2** KMS keys with restrictive key policies; rotation enabled.
- **IACS-SEC-3** Secret retrieval logged.
- **IACS-SEC-4** No hard-coded ARNs to other accounts that grant cross-account access without audit.

**Logging and monitoring:**
- **IACS-LOG-1** CloudTrail / Cloud Audit Logs / Activity Log enabled and exported to a separate account/project.
- **IACS-LOG-2** Log integrity validation enabled.
- **IACS-LOG-3** GuardDuty / Security Command Center / Defender for Cloud enabled.
- **IACS-LOG-4** Alerts on root login, IAM policy changes, security group changes.

### Phase 4: Triage

Critical class examples:
- Public S3 bucket containing user data
- IAM role with `*:*` policy attached to a production workload
- K8s pod with `privileged: true` reachable from public ingress
- Database publicly accessible
- IMDSv1 enabled with sensitive instance role

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `IACS-`.

## Tool integration

For each scanner the audit uses, document the command, the config file, and any baseline suppressions:

```yaml
# .checkov.yaml
skip-check:
  - CKV_AWS_18   # S3 access logging — covered by central log aggregation
```

Suppressions should have inline justifications. Treat unjustified suppressions as findings.

## References

- `references/dockerfile-hardening.md` — Multi-stage, non-root, distroless, scanning
- `references/k8s-hardening.md` — Pod Security Standards, network policies, RBAC
- `references/iam-least-privilege.md` — Policy design patterns, multi-cloud

## Scripts

- `scripts/run_iac_scanners.sh` — Runs tfsec, Checkov, Trivy in sequence with consistent output
