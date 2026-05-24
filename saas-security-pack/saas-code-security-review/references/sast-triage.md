# SAST Triage Reference

Load this when the user shares SAST output (CodeQL, Semgrep, Snyk Code, SonarQube) or asks how to prioritize a long list of static-analysis findings.

## The triage problem

SAST tools produce hundreds to thousands of findings on a mature codebase. Most are noise; some are real and Critical. The job is filtering, not blanket fixing.

## Confidence and impact dimensions

Triage on two axes:

| | Low impact | High impact |
|--|----------|-------------|
| **High confidence** | Fix in routine maintenance | Fix now |
| **Low confidence** | Suppress or rule-tune | Manual review |

- **High confidence** = the tool's rule is specific and false positives are rare in your codebase.
- **High impact** = exploitable in your context (reachable from untrusted input, in a security boundary).

## Common false positives by tool

### CodeQL

- **Path traversal warnings** on internal admin tooling where paths are operator-supplied — low impact unless admin tooling is exposed.
- **SQL injection in test files** — usually noise but verify the test file isn't included in production builds (it shouldn't be, but check).
- **Hard-coded credentials** that are obviously test placeholders (`password = "test123"` in unit tests).

### Semgrep

- **Generic regex matches** (`eval` in JS, `system` in Python) trigger on completely safe usages. Tune the ruleset.
- **Taint tracking gaps** — Semgrep's free version has limited cross-file taint analysis; many true positives appear as "you used `req.body` somewhere".

### Snyk Code

- **Cross-site scripting in unrelated paths** — Snyk traces taint optimistically and can flag chains that aren't reachable in practice.
- **License findings** in dev dependencies (often Snyk Open Source, not Code, but blended in reports).

### SonarQube

- **Cognitive complexity** warnings — code-quality, not security. Triage separately.
- **Cryptographically weak random** in non-crypto contexts (e.g., generating UI test IDs) — low impact.

## How to read a finding

For each finding, extract:

1. **Source** (where untrusted data enters)
2. **Sink** (where it's used dangerously)
3. **Path** (how source reaches sink)
4. **Sanitizer** (any function applied between them)
5. **Reachability** (is this code path actually invoked at runtime?)

If any of these is unclear from the SAST output, the tool's confidence is low — manual review needed.

## Triage workflow

For each finding, in 30 seconds or less:

1. Is the source actually untrusted? (e.g., is `req.body` actually attacker-controlled, or is it set by an internal service in the same trust boundary?)
2. Is the sink actually dangerous in this context? (e.g., `child_process.exec` with a shell-escaped, fixed-template command vs. raw user input)
3. Is there a sanitizer between source and sink that the tool missed?
4. Is the code path reachable? (e.g., dead code, deprecated route, behind a feature flag never enabled)

If all four point to "yes, exploitable" → real finding, prioritize by impact.

If any answer is "no" → mark as false positive in the tool (with comment so future runs ignore it) and document the reasoning.

## Suppression hygiene

When you suppress a finding:

- **Comment with the reason** in the suppression. `// nosemgrep: rule-id  reason: input is operator-only, no external reach`
- **Scope narrowly**. Suppress a specific line, not the whole file.
- **Re-review periodically**. Suppressions accumulate; quarterly review prevents legitimate findings from staying suppressed when the code around them changes.
- **Don't suppress with "fixed later"**. Either fix now or file a ticket linked from the suppression.

## Categorizing for the report

A useful bucketing when reporting back to the team:

| Bucket | What it contains | Action |
|--------|------------------|--------|
| **Fix now** | High confidence + reachable + real risk | Open PRs immediately |
| **Fix in next sprint** | High confidence + low immediate risk + on roadmap | Backlog item |
| **Suppress with note** | Confirmed false positive | Inline suppression + rule tuning |
| **Investigate further** | Low confidence + potentially serious | Manual code review |
| **Defer to rule tuning** | Same rule firing many false positives | Update ruleset/config |

For a 500-finding SAST report, expect roughly:
- 5-20 "fix now"
- 20-50 "fix in next sprint"
- 50-200 suppressions after triage
- 100-300 rule tuning candidates
- 10-30 "investigate further"

If your ratio is wildly different, your tool is misconfigured or your codebase has a systematic issue worth flagging.

## Reachability tools

Beyond what SAST tools provide natively:

- **CodeQL's `--threads`** + custom queries let you filter to "reachable from `routes/` directory".
- **Semgrep Pro** has reachability filtering against your runtime call graph.
- **`madge`** (JS) or `pyflakes` style tools can show which files are imported from your entry points.
- For Go: `go-callvis` or `guru` can produce reachable-from-main analyses.

Even a rough reachability filter ("is this file imported by any handler?") cuts noise by 30-50%.

## Output for the audit report

When the user asks "review my SAST output", produce:

1. **One-line summary**: "X findings; Y triaged as real, Z as false positive, W deferred."
2. **Top findings table** sorted by severity, with file:line and 1-sentence justification.
3. **Suppression candidates** with rationale.
4. **Rule tuning recommendations** (which rules to disable or scope).
5. **Reachability gaps** (where the tool couldn't determine reachability).

Avoid pasting the entire raw SAST output back at the user — that's their starting state, not the analysis they asked for.

## Integration into CI

Once a baseline is established, configure SAST in CI to:

- **Fail PRs that introduce new High/Critical findings** (not the whole backlog).
- **Track delta** rather than absolute count (existing findings don't block new PRs unless the PR touches them).
- **Use `fail-on: high`** (or equivalent) rather than `fail-on: any` — `any` causes alert fatigue and gets disabled.

This is "baseline + delta" mode and it's the practical way to ship SAST without blocking every PR on legacy noise.
