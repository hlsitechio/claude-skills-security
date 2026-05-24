# Kubernetes Hardening Reference

Load this when auditing Kubernetes manifests, Helm charts, or live cluster configuration.

## Pod Security Standards

Kubernetes defines three policy levels. Pick the strictest one your workloads support and enforce it via Pod Security Admission at the namespace level.

| Level | Posture | Use for |
|-------|---------|---------|
| `privileged` | Anything goes | System namespaces only |
| `baseline` | Blocks the worst (privileged, hostPID, hostNetwork, etc.) | Default-tolerant |
| `restricted` | Distroless-friendly, non-root, no capabilities | Application workloads |

Enforce on a namespace:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: app-production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

`enforce` blocks; `audit` logs; `warn` shows a warning when applying. Use all three for transparent rollout.

## Container securityContext — the minimum

Every container in production should have:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  fsGroup: 10001
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
  seccompProfile:
    type: RuntimeDefault
```

What each does:
- `runAsNonRoot` — Kubelet refuses to start the pod if the image's user is root.
- `runAsUser` / `runAsGroup` — explicit UID/GID (must match what the image expects to find).
- `allowPrivilegeEscalation: false` — prevents `setuid` binaries from escalating.
- `readOnlyRootFilesystem: true` — filesystem is read-only; force writes to declared `volumeMounts` (emptyDir for /tmp, etc.).
- `capabilities.drop: [ALL]` — strip every Linux capability. Add back only what's needed (`NET_BIND_SERVICE` if binding to port < 1024).
- `seccompProfile: RuntimeDefault` — applies the container runtime's default seccomp filter.

## Pod-level

```yaml
spec:
  automountServiceAccountToken: false   # unless the pod needs to call the API
  hostNetwork: false                     # default; assert it
  hostPID: false
  hostIPC: false
  serviceAccountName: app-specific-sa    # not "default"
```

`automountServiceAccountToken: false` is critical: by default, every pod gets a token to call the K8s API. Most apps don't need it. When it's mounted and the pod has a permissive SA, a container compromise = cluster compromise.

## Resource requests and limits

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Two functions:
- **Scheduler hint** (requests) — placement, capacity planning.
- **Cap** (limits) — one runaway container can't starve the node.

Missing limits = a memory leak or fork bomb takes down the node. Missing requests = bad scheduling. Both required for production.

## Network policy default-deny

Without NetworkPolicy, pods can talk to anything in the cluster — including the cloud metadata endpoint. Apply default-deny per namespace and add explicit allows:

```yaml
# Deny all ingress and egress by default
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: app-production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress

---
# Allow DNS (kube-dns / CoreDNS in kube-system)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: app-production
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53

---
# Allow your app to call your DB
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-to-db
  namespace: app-production
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes: [Egress]
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432
```

Note: CNI plugin must support NetworkPolicy (Cilium, Calico, Weave) — not all do. Confirm before relying on it.

Block egress to cloud metadata explicitly:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-imds
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32  # cloud metadata
              - 100.100.100.200/32  # alibaba metadata
```

Most CNI plugins support Cilium-style CIDR egress with `except`.

## ServiceAccount and RBAC

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api-sa
  namespace: app-production
automountServiceAccountToken: false

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: api-role
  namespace: app-production
rules:
  # ONLY what the app actually needs
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["app-config"]
    verbs: ["get"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: api-rolebinding
  namespace: app-production
subjects:
  - kind: ServiceAccount
    name: api-sa
    namespace: app-production
roleRef:
  kind: Role
  name: api-role
  apiGroup: rbac.authorization.k8s.io
```

Patterns to avoid:
- `verbs: ["*"]`
- `resources: ["*"]`
- `ClusterRoleBinding` to a namespace-scoped workload (it doesn't need cluster-wide).
- `system:masters` or any built-in admin group bound to application SAs.

## Secrets

```yaml
# AVOID: literal value in env
env:
  - name: DB_PASSWORD
    value: "supersecret"   # ⚠ visible in `kubectl describe`, in git if manifest is committed

# PREFER: secretKeyRef
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: db-credentials
        key: password
```

For real secret management, use one of:
- **External Secrets Operator** + AWS Secrets Manager / GCP Secret Manager / Vault — secrets stay in the manager; ESO syncs to k8s Secret.
- **Sealed Secrets** (Bitnami) — encrypted secret YAML that only the cluster controller can decrypt.
- **SOPS + age/KMS** — committed encrypted; CI/CD decrypts at apply time.

Plain k8s Secret is base64, NOT encrypted. Anyone with `get secrets` permission reads them. Enable etcd encryption at rest as defense-in-depth.

## Image pull

```yaml
image: registry.example.com/api@sha256:abc123...
imagePullPolicy: IfNotPresent
imagePullSecrets:
  - name: registry-creds
```

- Pull by digest (`@sha256:...`), not tag — tag is mutable.
- Use a private registry; don't depend on Docker Hub for production-critical images (rate limits + tag squatting risk).

## Ingress and TLS

- Always TLS at ingress (cert-manager + Let's Encrypt is easy in cluster).
- Block plaintext explicitly (`nginx.ingress.kubernetes.io/ssl-redirect: "true"`).
- Apply WAF rules at the ingress controller (NGINX + ModSecurity, or use Cloud Armor / Cloudflare in front).
- Set `proxy-body-size` and timeouts to reasonable limits.

## Admission policies

Run an admission controller that enforces baselines:

- **Kyverno** — YAML-based policies, easier to write.
- **Gatekeeper (OPA)** — Rego-based, more flexible.

Example Kyverno policy: "every deployment must have resource limits":

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-resource-limits
spec:
  validationFailureAction: Enforce
  rules:
    - name: validate-resources
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "Resource limits required."
        pattern:
          spec:
            containers:
              - resources:
                  limits:
                    memory: "?*"
                    cpu: "?*"
```

## Scanning manifests and runtime

- `kubesec` — static manifest scoring.
- `polaris` — static + runtime checks.
- `kube-bench` — CIS Kubernetes benchmark.
- `kube-hunter` — penetration testing (use on staging clusters only).
- `falco` — runtime threat detection (syscall-level).

CI integration:

```yaml
- run: kubesec scan deploy/*.yaml | jq '.[] | select(.score < 5)'
- run: polaris audit --audit-path ./manifests --severity danger
```

## Multi-tenancy in shared clusters

If you run multiple applications or tenants in the same cluster:
- Namespace per tenant + NetworkPolicy + ResourceQuota.
- LimitRange per namespace for default container limits.
- Pod Security Admission level `restricted` per app namespace.
- No `ClusterRole` exposing cross-namespace access to tenant SAs.

For higher isolation, separate clusters or virtual clusters (vcluster) per tenant.

## Audit checklist

For each Deployment/StatefulSet/DaemonSet:

1. Pod Security level set on its namespace (at least `baseline`, preferably `restricted`).
2. `runAsNonRoot: true`, `runAsUser` set.
3. `allowPrivilegeEscalation: false`.
4. `readOnlyRootFilesystem: true`.
5. `capabilities: { drop: [ALL] }`.
6. `seccompProfile.type: RuntimeDefault`.
7. Resource requests AND limits.
8. `automountServiceAccountToken: false` unless needed.
9. Dedicated ServiceAccount (not `default`).
10. NetworkPolicy default-deny in the namespace.
11. Image pinned by digest.
12. Secrets via `secretKeyRef`, not env literal.
13. Admission policy enforcing the above (Kyverno/Gatekeeper).
