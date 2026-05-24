# OIDC Cloud Authentication Reference

Load this when the user has long-lived cloud credentials in GitHub secrets or asks how to migrate to OIDC.

## Why OIDC instead of long-lived keys

GitHub Actions can mint short-lived OIDC tokens that workflows exchange for cloud credentials at runtime. Benefits over storing AWS access keys or GCP service account JSON keys as repo secrets:

- **No long-lived secret to leak**. The token is per-job, ~15 min, scoped.
- **Claims-based access control**. Cloud trust policies can require specific `repo`, `ref`, `environment`, or `workflow` claims.
- **Auditable**. Cloud-side logs show which workflow run assumed which role.

## AWS — assume an IAM role via OIDC

### One-time setup

1. Create the OIDC provider in IAM:
   - Provider URL: `https://token.actions.githubusercontent.com`
   - Audience: `sts.amazonaws.com`
   - Thumbprint: AWS now auto-validates the certificate chain; the legacy thumbprint requirement is removed for most regions but doesn't hurt.

2. Create an IAM role with this trust policy (least-privilege example for a specific repo and branch):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:yourorg/yourrepo:ref:refs/heads/main"
      }
    }
  }]
}
```

### Common `sub` claim patterns

| Pattern | Use case |
|---------|----------|
| `repo:org/repo:ref:refs/heads/main` | Production deploys from `main` only |
| `repo:org/repo:environment:production` | Production deploys from any branch, gated by Environment reviewers |
| `repo:org/repo:pull_request` | PR validation jobs (don't grant write to prod with this) |
| `repo:org/repo:*` | Any workflow in repo — usually too broad |

Prefer `environment:` over branch matching when possible — GitHub Environments add a UI gate (required reviewers, wait timers, deployment branch policies) on top of the OIDC claim.

### Workflow

```yaml
permissions:
  id-token: write   # required for OIDC
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@<sha>  # v4
      - uses: aws-actions/configure-aws-credentials@<sha>  # v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-actions-deploy
          aws-region: us-east-1
      - run: aws sts get-caller-identity  # sanity check
      - run: ./deploy.sh
```

### Detection patterns (anti-patterns)

- Repo or org secrets named `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`: high suspicion of long-lived key usage. Confirm and recommend OIDC migration.
- Trust policy with `"sub": "repo:org/*"` or no `sub` condition: way too broad.
- Trust policy missing `"aud"` condition: another claim should always be required alongside.
- IAM role with `AdministratorAccess` or `*:*` policies: should be scoped to deploy targets.

## GCP — Workload Identity Federation

### Setup

```bash
# Create pool and provider
gcloud iam workload-identity-pools create "github-pool" \
  --location="global" --display-name="GitHub Actions Pool"

gcloud iam workload-identity-pools providers create-oidc "github-provider" \
  --location="global" \
  --workload-identity-pool="github-pool" \
  --display-name="GitHub provider" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.ref=assertion.ref" \
  --attribute-condition="assertion.repository_owner == 'yourorg'" \
  --issuer-uri="https://token.actions.githubusercontent.com"

# Bind a service account to specific repo+ref
gcloud iam service-accounts add-iam-policy-binding \
  "deploy-sa@PROJECT.iam.gserviceaccount.com" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/NUM/locations/global/workloadIdentityPools/github-pool/attribute.repository/yourorg/yourrepo"
```

### Workflow

```yaml
permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>  # v4
      - uses: google-github-actions/auth@<sha>  # v2
        with:
          workload_identity_provider: 'projects/NUM/locations/global/workloadIdentityPools/github-pool/providers/github-provider'
          service_account: 'deploy-sa@PROJECT.iam.gserviceaccount.com'
      - run: gcloud auth list
```

### Detection patterns

- Secret named `GCP_SA_KEY` or any JSON-shaped service account key in secrets: long-lived key, migrate to WIF.
- `attribute-condition` missing or only checks `repository_owner`: should also constrain by `ref` or `environment` for production access.

## Azure — Federated Credentials on App Registration

### Setup

On the App Registration → Certificates & secrets → Federated credentials, add:
- Issuer: `https://token.actions.githubusercontent.com`
- Subject identifier: `repo:yourorg/yourrepo:environment:production`
- Audience: `api://AzureADTokenExchange`

### Workflow

```yaml
permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@<sha>
      - uses: azure/login@<sha>  # v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
      - run: az account show
```

Note: `client-id`, `tenant-id`, `subscription-id` are not secrets — they're identifiers. Use `vars:` not `secrets:`.

## Migration plan template

When the audit finds long-lived keys, propose this migration sequence:

1. **Inventory uses**. List every workflow that references the keys.
2. **Identify required permissions**. For each workflow, what cloud actions does it perform? Build the minimum policy.
3. **Create OIDC trust** in each cloud account, scoped to the specific repo and (ideally) environment.
4. **Test in a non-prod environment** before touching production. Run a dummy workflow that just assumes the role and calls `sts get-caller-identity` (or equivalent).
5. **Switch workflows** one at a time. Leave keys in place during the cutover.
6. **Rotate then delete the long-lived keys** after a quiet period (no workflow has used them).
7. **Add a guardrail**: a workflow that fails CI if any new long-lived cloud secret is added to the repo.

## Cross-cloud common mistakes

- Confusing OIDC token with cloud credentials. The OIDC token is exchanged for cloud creds — both must be configured.
- Forgetting `id-token: write` permission. Without it, the workflow can't request the OIDC token.
- Trust policy with no claim conditions beyond audience and provider. Anyone in the org (or worse, on the public GitHub) can assume the role.
- Using OIDC for the runner but still storing long-lived keys "as backup" — defeats the purpose.
