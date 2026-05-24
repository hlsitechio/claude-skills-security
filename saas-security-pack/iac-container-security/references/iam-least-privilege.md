# IAM Least Privilege Reference

Load this when reviewing IAM policies across AWS, GCP, or Azure.

## The core principle

Every principal (user, service account, role) should have exactly the permissions it needs — no more, no less, time-bounded where possible. The audit is hunting for over-grants and unbounded principals.

## Common over-grant patterns to flag

### Pattern 1 — `*:*` policies

```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

The IAM equivalent of `chmod 777 /`. Should appear only on a break-glass admin role with MFA and CloudTrail alerting. If attached to an application role: Critical finding.

GCP equivalent: `roles/owner` or `roles/editor` bound to a service account.
Azure equivalent: `Owner` or `Contributor` on a subscription bound to an SP.

### Pattern 2 — Wildcard action with sensitive prefix

```json
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*"
}
```

Better but still too broad: a bug that lets an attacker invoke `s3:DeleteBucket` deletes every bucket in the account.

Fix: enumerate the actions actually needed.

```json
{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject"
  ],
  "Resource": "arn:aws:s3:::my-app-bucket/*"
}
```

Use AWS IAM Access Analyzer "policy generation from CloudTrail" to discover what the workload actually used.

### Pattern 3 — Resource `*` when scope is known

```json
{
  "Effect": "Allow",
  "Action": "secretsmanager:GetSecretValue",
  "Resource": "*"
}
```

The workload only needs one secret. Resource: that secret's ARN, not `*`.

### Pattern 4 — `Principal: "*"` on resource policies

```json
// S3 bucket policy
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::my-bucket/*"
}
```

This makes the bucket publicly readable. Public bucket findings are Critical unless explicitly intended (static website assets, public docs).

For cross-account access, scope with `aws:SourceAccount` or `aws:SourceArn` conditions.

### Pattern 5 — Confused deputy without condition

```json
{
  "Effect": "Allow",
  "Principal": { "Service": "lambda.amazonaws.com" },
  "Action": "sts:AssumeRole"
}
```

Any Lambda in any AWS account can assume this role if they target the right ARN — confused deputy attack. Add `aws:SourceAccount`:

```json
{
  "Effect": "Allow",
  "Principal": { "Service": "lambda.amazonaws.com" },
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": { "aws:SourceAccount": "123456789012" }
  }
}
```

## Cross-cloud patterns

### AWS

**Use roles, not access keys.** Every workload assumes a role; no long-lived access keys for production workloads. OIDC for CI (see `github-supply-chain/references/oidc-cloud-auth.md`).

**Permission boundaries.** When delegating IAM management to application teams, attach a permission boundary that caps what the role can do regardless of attached policies.

```json
// Permission boundary
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:*", "dynamodb:*", "lambda:*"],
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "Action": ["iam:*", "organizations:*", "sts:AssumeRole"],
      "Resource": "*"
    }
  ]
}
```

**Service Control Policies (SCP)** at the organization level enforce guardrails across all accounts.

### GCP

**Service Account impersonation.** Long-lived service account keys are dangerous. Use Workload Identity Federation (for K8s and external CI), or `iam.serviceAccountTokenCreator` for short-lived tokens.

**Custom roles.** Predefined roles (`roles/editor`, `roles/viewer`) are often too broad. Build custom roles with `gcloud iam roles create` listing only required permissions.

**Conditional bindings.** IAM Conditions let you scope a binding by resource attributes, time, or origin:

```json
{
  "role": "roles/storage.objectAdmin",
  "members": ["serviceAccount:app@project.iam.gserviceaccount.com"],
  "condition": {
    "title": "Only on production bucket",
    "expression": "resource.name.startsWith('projects/_/buckets/prod-data')"
  }
}
```

### Azure

**Managed identities** (System-assigned or User-assigned) replace SP credentials. The Azure runtime injects tokens.

**RBAC scopes.** Bind roles at the resource, resource group, or subscription level — choose the narrowest scope that works.

**Privileged Identity Management (PIM)** for just-in-time elevation of privileged roles, time-bounded with approval.

## Specific actions worth special attention

These actions can be abused to escalate privilege; require an explicit reason for each grant:

| Cloud | Action | Why |
|-------|--------|-----|
| AWS | `iam:PassRole` | Lets the principal pass a role to a service that runs as that role. Combined with `lambda:CreateFunction`, attacker can run code as any role. |
| AWS | `iam:UpdateAssumeRolePolicy` | Modify who can assume a role — direct path to admin. |
| AWS | `iam:AttachUserPolicy`, `iam:PutUserPolicy` | Self-grant privileges. |
| AWS | `sts:AssumeRole` on broad ARNs | Allows lateral movement to other roles. |
| AWS | `kms:Decrypt` on broad keys | Read secrets. |
| AWS | `ec2:RunInstances` + role passing | Run code with high-priv role. |
| GCP | `iam.serviceAccounts.actAs` | Equivalent of `iam:PassRole`. |
| GCP | `iam.serviceAccounts.getAccessToken` | Mint tokens for other SAs. |
| Azure | `Microsoft.Authorization/roleAssignments/write` | Grant any role to anyone. |
| Azure | `*/Microsoft.KeyVault/...` | Read secrets. |

For each grant of any of these, document the necessity.

## Detection approach

### Static — scan IaC

```bash
# tfsec rules cover most overgrants
tfsec . --include-rule aws-iam-no-policy-wildcards

# Checkov has hundreds of IAM checks
checkov -d . --check CKV_AWS_40,CKV_AWS_41,CKV_AWS_62

# For broader coverage:
checkov -d . -o cli --quiet | grep -i iam
```

### Static — analyze actual policies in the cloud

```bash
# AWS — list all policies attached to roles
aws iam list-roles --query 'Roles[].RoleName' --output text \
  | xargs -n1 -I{} bash -c '
    echo "=== Role: {} ==="
    aws iam list-attached-role-policies --role-name {}
    aws iam list-role-policies --role-name {}
  '

# Then for each policy, fetch it and grep for *
```

### Behavioral — what did the role actually use?

AWS CloudTrail + Access Analyzer can generate a policy from actual usage:

```bash
aws accessanalyzer start-policy-generation \
  --policy-generation-details principalArn=arn:aws:iam::123456789012:role/my-app \
  --cloud-trail-details accessRole=arn:aws:iam::123456789012:role/access-analyzer-role,startTime=2024-01-01T00:00:00Z,trails=...
```

After 24 hours, retrieve the generated policy. Compare to current. Anything in current not in generated is over-grant.

GCP Recommender does similar for service accounts:

```bash
gcloud recommender recommendations list \
  --project=<project> \
  --recommender=google.iam.policy.Recommender \
  --location=global
```

## Just-in-time access patterns

For high-priv operations:

1. **AWS**: AssumeRole with MFA condition + IAM Identity Center (SSO) + temporary elevation.
2. **GCP**: PAM (Privileged Access Manager) — beta but useful for time-bounded elevation with approval.
3. **Azure**: PIM as mentioned.

Audit signal: are there any "long-running admin sessions" in CloudTrail / Cloud Audit Logs? Those indicate someone holding admin credentials beyond the necessary window.

## Service-to-service authentication

For microservices that call each other:
- **mTLS** via service mesh (Istio, Linkerd) — workload identity tied to certificate.
- **OIDC tokens** between services — short-lived, audience-scoped.
- **Internal API keys** are acceptable but harder to rotate and audit.

The pattern to avoid: a single "internal service account" with broad permissions shared across many services.

## Audit checklist

For each role / service account / managed identity:

1. Trust policy / principal scoped to the specific consumer.
2. Permission set enumerated (no wildcards on actions where possible).
3. Resource scoped (no `*` on resource unless the action genuinely requires it).
4. No long-lived credentials when short-lived alternatives exist.
5. Conditions/SCPs/permission boundaries cap the role's authority.
6. Privileged actions (PassRole, ActAs, RoleAssignments/Write) reviewed individually.
7. Usage data (CloudTrail / Cloud Audit / Activity Log) reviewed against grants; drop unused permissions.
8. Sensitive grants (KMS, Secrets, IAM management) require MFA or PIM for human users.
