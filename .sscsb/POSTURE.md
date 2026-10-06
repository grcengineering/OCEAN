# sscsb posture — what is not green, and why

`sscsb verify` is the source of truth; this file exists so that the items it does not
report as `PASS` have a written reason instead of becoming background noise everyone
learns to scroll past. Re-read it whenever `sscsb verify` changes.

Last reconciled: **2026-09-12**, against `sscsb 0.4.0`.
State at that time: **27 PASS · 1 FAIL · 1 DEGRADED · 3 INFO · 15 disabled**.

---

## FAIL — `branch-protection`

Not fixable from the tree: a ruleset lives in GitHub's settings, and `sscsb harden
branch-protection` cannot write this one because it looks for a ruleset that names the
branch literally while ours targets the `~DEFAULT_BRANCH` alias.

The three missing rules — required pull requests, required signed commits, required
status checks — are written out as an importable ruleset in
[`.github/rulesets/main-branch-protection.json`](../.github/rulesets/main-branch-protection.json),
with the reasoning and the one-line `gh api` command in the README beside it. Applying
it is an owner action; `sscsb verify branch-protection` confirms it afterwards.

---

## DEGRADED — `signing-model`

Two different reasons, and only one of them is a gap.

### 1. Lanes that have no read API (`github-web`, `codespaces`, `cloud-claude`)

Vigilant mode, passkey enrollment, Codespaces GPG verification, and the GitHub App
install are web settings that GitHub exposes no API for. sscsb therefore records a
*dated attestation by the owner* rather than proving them, via
`sscsb signing setup <lane> --confirm`. Nobody else can make that attestation truthfully
— asserting it on the owner's behalf would put an unverified claim into the audit
trail, which is precisely the failure mode this control exists to prevent. It stays
un-attested until the owner runs those commands.

### 2. `agent-claude-code` — deliberately NOT converged

sscsb wants a `GIT_CONFIG_*` env block in the agent's settings so that agent commits
carry a **distinct agent identity** and never fall through to the human's.

This repository's owner runs the opposite policy, and it is deliberate: **one signer,
everywhere.** Every commit — human or agent-assisted — signs as the owner with their
1Password-vaulted SSH key, which is registered as an approved human signer in
[`.sscsb/policy/signers.toml`](policy/signers.toml) (see also commit `a71bd13`). A
separate unverified agent identity was retired on purpose; AI involvement is recorded
through the `AI-Assisted` / `AI-Tool` / `AI-Model` / `AI-Role` commit trailers that the
`ai-trailers` control enforces, not through a second key.

Converging this lane would reintroduce the identity split the owner removed. It is
left un-converged on purpose, and this note is the record of that decision. If the
policy ever changes, run `sscsb signing setup agent-claude-code`.

---

## INFO — informational, not gaps

| Control | Why it is INFO |
|---------|----------------|
| `scorecard` | Reports live OpenSSF Scorecard findings. Each is routed to the sscsb control that gates it. The two that remain unroutable are `CIIBestPractices` (register the project at bestpractices.dev — an owner action no tool can perform) and `CodeReview` (Scorecard counts *approved* changesets; a solo maintainer cannot self-approve, so it is capped at 0 until there is a second reviewer). |
| `secure-repo` | StepSecurity secure-repo is a hosted web service, not an action. Nothing to install. |
| `openvex` | No VEX documents exist because there is nothing to waive: `vuln-scan` currently reports 2 findings and 0 at or above `high`. A VEX document should appear only when a specific advisory is deliberately triaged as not-affected. |

---

## Known sscsb defect this repository runs into

**`sscsb 0.4.0`'s pre-push range scan ignores `[controls.secrets].gitleaks = false`.**

The pre-commit path reads the toggle (`src/hooks.rs:610`, `let want_gl =
cfg.control_opt_bool("secrets", "gitleaks")`). The pre-push range path
(`src/hooks.rs:1329`) does not — it runs gitleaks whenever the binary is on PATH,
whatever the config says. `trufflehog` in the same function is ungated the same way.

(The range path also omits the staged path's explicit `--config .gitleaks.toml`, but
that one is harmless: gitleaks resolves a `.gitleaks.toml` at the scan root on its
own. Measured on this repository — 20 findings with the file absent, 16 with it
present, the four `ade.lock.json` hits being the ones its allowlist covers. So the
repo config is applied either way, and restoring it would not unblock anything.)

Two consequences here:

1. Turning gitleaks off in `.sscsb/config.toml` silences it on commit but not on
   push, so this repository cannot actually reach "TruffleHog only" on a machine
   that has gitleaks installed until sscsb is fixed.
2. When the pushed branch does not yet exist on the remote, `remote_sha` is the
   zero sha and the scan range collapses to `--log-opts=<local_sha>` — the branch's
   ENTIRE history rather than the commits being pushed. On this repository that
   reports 16 findings, every one of them a false positive in code that has been on
   `main` for months: Go file-path strings (`ocean-ed25519.key`) from the
   implementation deleted in `81a7e3f`, `Authorization:` header examples in
   `docs/quickstart.md`, a research note, and the masking helper in
   `src/harden/mod.rs`. TruffleHog over the identical range reports nothing, which is
   the whole argument for preferring it. Over the range actually being pushed
   (`f565d53..HEAD`) BOTH scanners report nothing — the findings are an artifact of
   the range, not of the change.

A gate that fails closed on twenty false positives is a gate people learn to push
past with `--no-verify`. Do not do that. Fix it in sscsb: gate the range-scan
gitleaks block on the same `control_opt_bool` the staged path uses, pass the repo's
`.gitleaks.toml` when present, and derive the range from the merge-base with the
default branch when the remote ref does not exist yet.

---

## Deliberate tool choices

- **Secret scanning runs TruffleHog and Gitleaks together.** gitleaks was removed on
  2026-09-12 and restored on 2026-10-06 (owner decision). TruffleHog *validates* a
  candidate against the issuing provider, so `verified` means a live credential, and
  that stays the stronger signal where it applies. But `--results=verified,unknown`
  drops anything TruffleHog cannot validate, and gitleaks' entropy/regex matching
  catches generic secrets (e.g. a bare `api_key = "..."` literal) and unverifiable
  keys in that gap. The two tools are complementary, not redundant.
- **SAST runs three engines on purpose.** CodeQL (interprocedural taint tracking over a
  compiled database), OpenGrep, and Semgrep model different vulnerability classes;
  CodeQL surfaces findings an OpenGrep default ruleset does not express at all. This is
  not redundancy of the kind gitleaks was.
