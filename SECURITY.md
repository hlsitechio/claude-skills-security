# Security Policy

This repository ships defensive-security audit skills for Claude. The skills themselves are markdown content — they don't run any code on a user's behalf — but a flaw in the *content* (e.g., a check that recommends an insecure pattern, a code example with a subtle bug, a missing CVE reference) can still propagate to downstream audits.

## Reporting a vulnerability

Two channels, in order of preference:

1. **GitHub private vulnerability report** — https://github.com/hlsitechio/claude-skills-security/security/advisories/new (only the maintainer is notified; no public disclosure until coordinated).
2. **Email** — `hlarosesurprenant@gmail.com` with `[claude-skills-security]` in the subject.

Include:
- The skill file (`<pack>/<skill>/SKILL.md` or `<pack>/<skill>/references/<name>.md`) and a line range.
- The specific check / example you believe is wrong, dangerous, or missing.
- An authoritative source (vendor advisory, CVE, RFC, web.dev / Chrome blog) that supports the claim.
- A suggested fix if you have one.

## What counts as a vulnerability here

- A check that **recommends an insecure pattern** as if it were safe.
- A code example whose intent is "GOOD" but which has a subtle flaw that would land in a real audit report.
- A **missing CVE / advisory** for a tech we track in [`.github/tech-inventory.yml`](.github/tech-inventory.yml) — particularly Critical / High severity ones referenced by upstream vendors.
- A path in the skill content that would lead a downstream user to deploy a vulnerable configuration.

## What is NOT a vulnerability

- A check that you'd phrase differently. Open a PR.
- A skill that doesn't cover a topic you care about. Open an issue.
- A reference to a non-canonical source. Open a PR with a better source.

## Response timeline

- Acknowledge within **3 business days**.
- Triage to severity (Critical / High / Medium / Low) within **7 days**.
- Critical fixes shipped within **14 days** of confirmation.
- Coordinated disclosure: 90 days unless we agree a different window.

## Defensive-only scope

This pack is intentionally defensive. We do not accept reports framed as "this skill should help an attacker" — that's out of scope by design (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Credit

Reporters are credited in the release notes for the fix unless they ask to remain anonymous.
