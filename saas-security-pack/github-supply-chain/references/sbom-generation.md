# SBOM Generation Reference

Load this when checking whether the repo produces SBOMs, what format, and how they're attested.

## Formats

| Format | Origin | Use when |
|--------|--------|----------|
| **CycloneDX** | OWASP | Default for application SBOMs; rich vulnerability and license metadata. JSON or XML. |
| **SPDX** | Linux Foundation / ISO 5962 | Required by some procurement (US gov, EU CRA). JSON, YAML, or tag-value. |
| GitHub dependency graph export | GitHub | Quick start; less portable than CycloneDX or SPDX. |

If unsure, produce both — generation cost is negligible.

## Generation tools

| Tool | Languages/targets | Output |
|------|-------------------|--------|
| [`syft`](https://github.com/anchore/syft) | Containers, dirs, archives, lockfiles for most ecosystems | CycloneDX, SPDX |
| [`cdxgen`](https://github.com/CycloneDX/cdxgen) | Wide language support, deep dependency analysis | CycloneDX |
| `npm sbom` | npm projects (native) | CycloneDX, SPDX |
| GitHub `dependency-graph/export-sbom` | Any repo with dependency graph enabled | SPDX |

`syft` is the most common choice for CI: one tool, every ecosystem.

## Workflow example

```yaml
name: Release with SBOM
on:
  push:
    tags: ['v*']

permissions:
  contents: write       # for release upload
  id-token: write       # for Cosign keyless signing
  attestations: write   # for build attestation

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>  # v4

      - name: Build artifact
        run: ./build.sh

      - name: Generate SBOM (CycloneDX)
        uses: anchore/sbom-action@<sha>  # v0
        with:
          path: ./dist
          format: cyclonedx-json
          output-file: sbom.cdx.json

      - name: Generate SBOM (SPDX)
        uses: anchore/sbom-action@<sha>  # v0
        with:
          path: ./dist
          format: spdx-json
          output-file: sbom.spdx.json

      - name: Sign SBOMs with Cosign (keyless)
        uses: sigstore/cosign-installer@<sha>  # v3
      - run: |
          cosign sign-blob --yes sbom.cdx.json --output-signature sbom.cdx.json.sig
          cosign sign-blob --yes sbom.spdx.json --output-signature sbom.spdx.json.sig

      - name: Generate SLSA build attestation
        uses: actions/attest-build-provenance@<sha>  # v1
        with:
          subject-path: 'dist/*'

      - name: Upload as release assets
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh release upload "${{ github.ref_name }}" \
            sbom.cdx.json sbom.cdx.json.sig \
            sbom.spdx.json sbom.spdx.json.sig
```

## Container images — SBOM as OCI attestation

For container artifacts, attach the SBOM to the image itself so it travels with the image across registries:

```yaml
- name: Build and push image
  uses: docker/build-push-action@<sha>  # v6
  with:
    context: .
    push: true
    tags: ghcr.io/${{ github.repository }}:${{ github.sha }}
    sbom: true                # produces CycloneDX SBOM
    provenance: mode=max      # SLSA provenance

- name: Sign image with Cosign
  run: |
    cosign sign --yes ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
```

Consumers verify with:
```bash
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp 'https://github.com/yourorg/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/yourorg/yourimage:sha-abc123
```

## SLSA levels

| Level | Requirement |
|-------|-------------|
| L1 | Build process is automated and produces provenance |
| L2 | Provenance is signed by a hosted build service (e.g., GitHub Actions runner with OIDC) |
| L3 | Hardened build platform (ephemeral, isolated, no user-supplied tampering) |
| L4 | Hermetic and reproducible builds, two-person review |

`actions/attest-build-provenance` produces L2 attestations out of the box. L3 requires running on isolated runners (e.g., GitHub-hosted larger runners with no extension, or custom hardened self-hosted).

## What an audit checks

1. **Existence**: at least one of `sbom.cdx.json`, `sbom.spdx.json`, or equivalent is produced per release.
2. **Storage**: SBOM is uploaded as a release asset or pushed to an SBOM registry. Not just printed to workflow logs (logs expire).
3. **Signature**: SBOM blob is signed (Cosign keyless or with a project key).
4. **Coverage**: every release artifact has a corresponding SBOM. If the project produces multiple artifacts, each gets its own.
5. **Format alignment with consumers**: if downstream needs SPDX (regulatory), CycloneDX-only is a gap.
6. **Provenance**: SLSA L2+ attestation present for production artifacts.

## Common findings

- **SBOM-MISSING**: project ships releases without any SBOM. Severity Medium; High if regulated.
- **SBOM-UNSIGNED**: SBOMs exist but are not signed. Lets a registry MITM swap the SBOM for a clean one. Severity Medium.
- **SBOM-INCOMPLETE**: SBOM covers `node_modules` but not the bundled binaries it embeds. Severity Low to Medium.
- **PROV-MISSING**: no build provenance attestation. Severity Low to Medium depending on threat model.

## Verification snippet for the report

When recommending SBOM generation, also recommend a downstream verification step the team can hand to customers:

```bash
# Customer-side verification
gh release download v1.2.3 --repo yourorg/yourrepo \
  --pattern 'sbom.cdx.json*'
cosign verify-blob \
  --signature sbom.cdx.json.sig \
  --certificate-identity-regexp 'https://github.com/yourorg/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  sbom.cdx.json
```
