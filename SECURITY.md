# Security Policy

OCEAN is security tooling. A defect here can mislead someone about the state of a
control they believe is enforced, so we treat correctness of evidence and verdicts
as a security property, not just a quality one.

## Reporting a vulnerability

**Report privately. Do not open a public issue for a vulnerability.**

Use GitHub's private vulnerability reporting on this repository:

1. Go to <https://github.com/grcengineering/OCEAN/security/advisories/new>
2. Describe the issue, the affected version or commit, and the impact.
3. Include a reproduction — a minimal check, manifest, evidence document, or
   command line — wherever one exists.

Private vulnerability reporting is enabled on this repository, so the report is
visible only to the maintainers until an advisory is published.

If you cannot use GitHub advisories, contact the maintainers at
<team@grc.engineering> and say that the message concerns a security issue in OCEAN.

### What to expect

| Stage | Target |
|-------|--------|
| Acknowledgement of the report | 3 business days |
| Initial assessment (severity, affected versions) | 10 business days |
| Fix or documented mitigation for a confirmed HIGH/CRITICAL | 30 days |
| Public advisory | on release of the fix, crediting the reporter unless they ask otherwise |

We will tell you if we disagree that a report is a vulnerability, and why.

## Supported versions

OCEAN is pre-1.0. Only the default branch (`main`) and the most recent release
receive security fixes; there are no maintained release branches yet.

| Version | Supported |
|---------|-----------|
| `main` | ✅ |
| latest release | ✅ |
| anything older | ❌ |

## In scope

- Evidence, check, or control handling that yields a **wrong verdict** — a control
  reported as passing when the observed evidence does not support it, or evidence
  attributed to the wrong source.
- Path traversal, arbitrary file read/write, or command injection reachable from a
  check, pack, manifest, config, or evidence document (including untrusted ones).
- Credential handling defects: a secret written to disk unmasked, logged, emitted in
  a report or SARIF file, or sent to an unintended host.
- Expression-evaluation escapes (CEL) and deserialization defects in the loaders.
- Supply-chain defects in this repository's own build, release, signing, or
  provenance pipeline.

## Out of scope

- Vulnerabilities in the third-party platforms OCEAN observes — report those to the
  vendor. We will help you route the report if it is unclear where it belongs.
- Findings that require an attacker who already has write access to the machine
  running OCEAN, or to this repository.
- Missing hardening with no demonstrated impact, and automated-scanner output
  submitted without a reachability argument.

## How this repository is defended

These are enforced in CI and by the local git hooks, not aspirational:

- **Secret scanning** — TruffleHog, with provider validation
  (`--results=verified,unknown`), at pre-commit, pre-push, and on every pull request,
  plus GitHub secret scanning with push protection.
- **SAST** — CodeQL (interprocedural taint analysis), OpenGrep, and Semgrep. They
  model different vulnerability classes and are run together deliberately.
- **Dependencies** — `cargo audit`, `cargo deny`, `cargo vet`, Trivy, OSV-Scanner,
  Socket, and Renovate with digest pinning.
- **Fuzzing** — `cargo-fuzz` targets for the CEL evaluator, the check loader, and the
  YAML manifest parser.
- **Build integrity** — SHA-pinned GitHub Actions, StepSecurity Harden-Runner on every
  job, SLSA provenance, Sigstore/Cosign signing, SBOM attestation, and verification
  gates before publish.
- **Posture verification** — `sscsb verify` over the control set defined in
  `.sscsb/config.toml`.
