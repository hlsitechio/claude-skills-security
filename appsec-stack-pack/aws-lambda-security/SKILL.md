---
name: aws-lambda-security
description: Security audit for AWS Lambda functions including IAM role least privilege, environment variable encryption (KMS), Function URLs vs API Gateway, VPC config, layer usage, container image scanning, X-Ray and logs PII, cold start state, async invocation handling, and Lambda-specific patterns across Node, Python, Go, Java runtimes. Use this skill whenever the user mentions AWS Lambda, lambda function, IAM role, Function URL, API Gateway + Lambda, Lambda layer, SAM, CDK Lambda, Serverless Framework, or asks "audit my Lambda", "Lambda security review", "Lambda IAM". Trigger when the codebase contains `serverless.yml`, `template.yaml` (SAM), `cdk.json`, or Lambda handler patterns.
---

# AWS Lambda Security Audit

Audit AWS Lambda functions across runtimes (Node, Python, Go, Java, .NET, Ruby).

## When this skill applies

- Reviewing Lambda IAM roles and policies
- Auditing function configuration (env vars, VPC, timeout, memory)
- Reviewing Function URL vs API Gateway exposure
- Checking layer dependencies and supply chain
- Auditing handler code for runtime-agnostic Lambda concerns

## Workflow

Follow `../_shared/audit-workflow.md`. Companion: runtime-specific skills (`nodejs-express-security`, `fastapi-security`, etc.).

### Phase 1: Stack detection

```bash
# IaC discovery
ls serverless.yml serverless.yaml template.yaml template.yml cdk.json 2>/dev/null
# Check AWS CLI
aws --version 2>/dev/null
# SAM
ls samconfig.toml 2>/dev/null
```

### Phase 2: Inventory

```bash
# Function definitions
grep -rn 'AWS::Lambda::Function\|Type: AWS::Serverless::Function\|new Function(' . --include='*.yml' --include='*.yaml' --include='*.ts' --include='*.py' 2>/dev/null

# IAM policies
grep -rn 'Policies:\|PolicyDocument\|inlinePolicies' . --include='*.yml' --include='*.yaml' --include='*.ts' 2>/dev/null | head

# Function URLs
grep -nE 'FunctionUrlConfig|addFunctionUrl' . --include='*.yml' --include='*.yaml' --include='*.ts' 2>/dev/null

# Env vars
grep -nE 'Environment:|environment:' . --include='*.yml' --include='*.yaml' 2>/dev/null | head
```

### Phase 3: Detection — the checks

#### IAM — least privilege

- **AWL-IAM-1** Each function has its own role. Don't share one fat role across functions.
- **AWL-IAM-2** Policies grant specific actions on specific resources (no `*`).
  ```yaml
  # BAD
  Policies:
    - Action: '*'
      Resource: '*'
  
  # GOOD
  Policies:
    - Action:
        - dynamodb:GetItem
        - dynamodb:PutItem
      Resource:
        - !Sub 'arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/Users'
  ```
- **AWL-IAM-3** No `iam:PassRole`, `iam:CreateRole`, `sts:AssumeRole` unless needed (and then scoped).
- **AWL-IAM-4** No `kms:Decrypt: *` — limit to specific keys.
- **AWL-IAM-5** Service-linked roles (e.g., `AWSLambdaVPCAccessExecutionRole`) granted only when VPC actually needed.
- **AWL-IAM-6** Resource-based policies on Lambda (`AWS::Lambda::Permission`) restrict who can invoke (specific principal, source ARN).

#### Function URL exposure

Function URLs are public HTTPS endpoints without API Gateway. They're easy and risky.

- **AWL-URL-1** Function URLs use `AuthType: AWS_IAM` if not public; `NONE` only for genuinely public endpoints.
- **AWL-URL-2** With `AuthType: NONE`, the Lambda code is the only line of defense — every request validated.
- **AWL-URL-3** CORS configured at the Function URL level for browser-facing URLs (specific origins).
- **AWL-URL-4** Function URL invokes only the function's `$LATEST` or a specific alias; not used to expose internal functions.

#### API Gateway integration

If behind API Gateway:

- **AWL-AG-1** API Gateway authorizers configured (Lambda Authorizer, Cognito, JWT) for non-public endpoints.
- **AWL-AG-2** API keys + usage plans for B2B APIs.
- **AWL-AG-3** Throttling configured per route.
- **AWL-AG-4** Request validation at API Gateway level (catches malformed requests before Lambda invocation, reducing cost surface).
- **AWL-AG-5** Resource policies restrict access to specific VPCs / IPs if private.

#### Environment variables

- **AWL-ENV-1** Sensitive env vars encrypted with KMS (`KmsKeyArn`). Default AWS-managed key works; CMK for sensitive cases.
- **AWL-ENV-2** Encryption helpers used to decrypt at runtime, with cache so KMS isn't called every invocation.
- **AWL-ENV-3** Secrets fetched from Secrets Manager / Parameter Store at cold start, NOT in env vars (rotation works).
- **AWL-ENV-4** No secrets in CloudFormation parameters without `NoEcho: true`.

#### VPC configuration

- **AWL-VPC-1** Functions in VPC only when needed (database access, internal APIs). VPC adds cold start latency.
- **AWL-VPC-2** Security groups restrict outbound to specific destinations.
- **AWL-VPC-3** Subnets are private; NAT Gateway / VPC Endpoints for outbound.
- **AWL-VPC-4** Lambda doesn't need internet → use VPC endpoints (PrivateLink) instead of NAT.

#### Reserved / provisioned concurrency

- **AWL-CC-1** Reserved concurrency caps functions that have downstream rate limits or backend bottlenecks.
- **AWL-CC-2** Provisioned concurrency for latency-sensitive functions; not enabled needlessly (cost).

#### Cold start state leakage

Lambda containers persist across invocations from the same warm runtime. Module-level state leaks across users.

```js
// BAD — caches per-user data in module scope
let currentUser;
exports.handler = async (event) => {
  currentUser = event.user;   // overwritten by next invocation
  return process(currentUser);
};

// GOOD — per-invocation scope only
exports.handler = async (event) => {
  const user = event.user;
  return process(user);
};
```

- **AWL-CS-1** No mutable module-scope state holding per-request data.
- **AWL-CS-2** Connection pools (DB, HTTP) initialized at cold start are OK; per-request state in invocation scope.

#### Timeouts and memory

- **AWL-TO-1** Function timeout appropriate (default 3s; max 15min). Excessive timeout = DoS amplifier.
- **AWL-TO-2** Memory size tested; underprovisioning causes slow execution + cost; overprovisioning is waste but not security.

#### Layers and dependencies

- **AWL-LY-1** Lambda Layers from your own account or trusted publishers (AWS, well-known). Public layer ARNs verified.
- **AWL-LY-2** Layer versions pinned; auto-update not in use without testing.
- **AWL-LY-3** Bundled dependencies (zip) scanned (`pip-audit`, `npm audit`, etc.) before deploy.

#### Container image deployment

If Lambda uses container images:

- **AWL-CT-1** Base image from trusted source; minimal (distroless, alpine).
- **AWL-CT-2** Image scanned (ECR scanning, Snyk, Trivy) before deploy.
- **AWL-CT-3** Image doesn't contain build secrets (multi-stage build hides them).

#### Async invocation and DLQ

- **AWL-AS-1** Dead-letter queue configured for async invocations; failures don't disappear.
- **AWL-AS-2** Retry config (`Maximum Retry Attempts`) appropriate; not retrying poison messages indefinitely.
- **AWL-AS-3** Idempotency for async handlers (S3 event, SQS, etc.) — same event may invoke multiple times.

#### Logs and X-Ray

- **AWL-LOG-1** CloudWatch Logs retention set (default infinite; choose 30-90 days for production, longer for compliance).
- **AWL-LOG-2** Sensitive data not logged. CloudWatch Logs are searchable by IAM-authorized users.
- **AWL-LOG-3** X-Ray sampling configured; traces don't include raw request bodies.

#### Event source mappings

- **AWL-ESM-1** SQS / Kinesis / DynamoDB streams as event sources — Lambda role has only `Read/Delete` permissions on the source.
- **AWL-ESM-2** Cross-account event source: source ARN restricted.

#### Signing / code integrity

- **AWL-SIG-1** Code Signing Configuration enabled for production functions if compliance requires.
- **AWL-SIG-2** Signing profile and signed deployment package via AWS Signer.

#### Throttling / DoS protection

- **AWL-DOS-1** Account concurrency limit known and monitored; one runaway function shouldn't exhaust account limit.
- **AWL-DOS-2** Function-level reserved concurrency (per AWL-CC-1).
- **AWL-DOS-3** Async invocation queues bounded (DLQ catches overflow).

#### Deployment

- **AWL-DEP-1** CI/CD deploys with assume-role + short-lived creds; not long-lived IAM user keys.
- **AWL-DEP-2** Production deploy gated; staging tested first.

### Phase 4: Triage

Critical: IAM role with `*:*`; secrets in plain env vars; Function URL with AuthType NONE and no in-code auth; module-scope mutable state across invocations.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `AWL-`.
