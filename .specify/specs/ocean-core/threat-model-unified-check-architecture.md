# Threat Model: Unified Check Architecture (ADR-001)

**Owner:** CISO
**Status:** Complete
**Date:** 2026-03-28
**Scope:** OCEAN + HTH merge — `.check.yaml` meta-code format, runtime interpreter, code pack generation, remediation engine, community check contributions
**Related:** ADR-001 (`adr-001-unified-check-architecture.md`), Spec (`spec.md`)

---

## 1. Assets

| ID | Asset | Sensitivity | Location |
|----|-------|-------------|----------|
| A1 | API credentials (GITHUB_TOKEN, AWS keys, Okta API keys) | **Critical** — org-admin-scoped tokens granting read/write to target systems | Environment variables, config files, `.check.yaml` `credentials:` block |
| A2 | Target system configuration state | **High** — org security settings, member lists, repo configs | API responses, SQLite evidence store, JSON output |
| A3 | `.check.yaml` definitions (bundled + user drop-in) | **High** — define arbitrary HTTP requests and remediation actions | `checks/`, `~/.ocean/checks/`, `--checks-dir` paths |
| A4 | Remediation actions | **Critical** — PATCH/PUT/DELETE calls that mutate target system state | `.check.yaml` `remediation.api:` block, `ocean harden` execution |
| A5 | Generated code packs | **Medium** — standalone scripts containing API call patterns | `packs/` directory, committed to repo |
| A6 | SQLite evidence database | **Medium** — historical control evaluation results, org metadata | Local filesystem, `ocean history` |
| A7 | CEL evaluation engine | **Medium** — expression evaluation against extracted data | Runtime, `src/eval/` |
| A8 | REST API server | **High** — network-accessible interface to all OCEAN capabilities | `ocean serve`, axum on configurable port |
| A9 | Handlebars templates | **Medium** — code generation templates for all target languages | `src/codegen/templates/` |

## 2. Threat Actors

| Actor | Motivation | Capability |
|-------|-----------|------------|
| **Malicious check author** | Supply chain — inject malicious checks via community contribution or drop-in directory | Can craft `.check.yaml` files that exfiltrate credentials, make unauthorized API calls, or trigger destructive remediation |
| **Compromised CI/CD** | Tamper with check definitions or generated code packs during build | Can modify files in the repo, inject content into generated packs |
| **Local attacker (shared machine)** | Steal credentials, tamper with evidence, corrupt checks | File system access to `~/.ocean/`, environment variables, SQLite DB |
| **Network attacker (MITM)** | Intercept API credentials in transit, tamper with API responses | Network position between OCEAN and target APIs |
| **Malicious dependency** | Supply chain compromise via Cargo crate | Code execution within OCEAN process |

## 3. Attack Surfaces & Vectors

### 3.1 `.check.yaml` Injection (CRITICAL)

**Surface:** The YAML check loader (`src/check/loader.rs`) parses and executes arbitrary `.check.yaml` files from multiple paths: bundled, user drop-in (`~/.ocean/checks/`), and custom (`--checks-dir`).

**Vectors:**
- **T1: Credential exfiltration via check steps.** A malicious check defines `steps:` that POST credentials to an attacker-controlled URL. The `request.url` field accepts arbitrary URLs with template variables including `{{GITHUB_TOKEN}}`.
- **T2: SSRF via check steps.** A check targets internal network endpoints (169.254.169.254, localhost, internal services) using the HTTP client.
- **T3: Destructive remediation.** A check's `remediation.api:` block issues DELETE or destructive PATCH calls. `ocean harden` executes these.
- **T4: YAML deserialization attacks.** `serde_yaml` processes untrusted YAML — billion laughs, alias bombs, or unexpected type coercion.
- **T5: Path traversal in check loading.** `--checks-dir` or symlinks in `~/.ocean/checks/` could escape intended directories.

**Mitigations (required before Phase 1 implementation):**

| ID | Mitigation | Priority |
|----|-----------|----------|
| M1 | **URL allowlist for check steps.** Check `request.url` must match a known set of API base URLs per source system (e.g., `https://api.github.com/*` for `source: github`). Reject arbitrary URLs. | P0 |
| M2 | **SSRF protection.** Block requests to RFC 1918 addresses, link-local (169.254.x.x), localhost, and cloud metadata endpoints. Use a URL validator before every HTTP call in the interpreter. | P0 |
| M3 | **Credential scoping.** Credentials declared in `credentials:` block are only passed to URLs matching the source system's allowlist. Never inject credentials into arbitrary request URLs. | P0 |
| M4 | **Remediation confirmation gate.** `ocean harden` must require explicit `--confirm` flag (or interactive prompt) before executing any mutating API calls. `--dry-run` is the default for remediation. | P0 |
| M5 | **YAML parsing limits.** Configure `serde_yaml` with depth limits. Reject YAML files exceeding a size threshold (e.g., 1MB). Validate against JSON Schema before interpretation. | P1 |
| M6 | **Check signature/hash verification.** Bundled checks are verified against a manifest hash. User drop-in checks display a warning on first load: "Unverified check from ~/.ocean/checks/". | P1 |
| M7 | **Path canonicalization.** Resolve all check load paths to canonical absolute paths. Reject symlinks pointing outside the intended directory. | P1 |

### 3.2 Template Variable Injection (HIGH)

**Surface:** Template variables (`{{org}}`, `{{GITHUB_TOKEN}}`) are resolved in URLs, headers, and request bodies.

**Vectors:**
- **T6: Injection via input values.** If `org` is set to `../../admin` or contains URL-encoded payloads, it could alter the request path or query string.
- **T7: Header injection.** Template variables in headers could inject additional headers via CRLF sequences.
- **T8: CEL injection.** If extracted values flow into CEL expressions unsafely, an attacker could craft API responses that alter assertion outcomes.

**Mitigations:**

| ID | Mitigation | Priority |
|----|-----------|----------|
| M8 | **Input sanitization.** Validate all `inputs:` values against expected patterns (alphanumeric + hyphens for org names, etc.). Reject values containing path traversal sequences, CRLF, null bytes. | P0 |
| M9 | **URL encoding.** Template variables interpolated into URLs must be properly URL-encoded. Use Rust's `url` crate for URL construction, not string concatenation. | P0 |
| M10 | **CEL expression safety.** Assertions are defined in the check file (trusted), not constructed from extracted values. Extracted values are data inputs to CEL, not code. Verify this invariant in the interpreter. | P1 |
| M11 | **Header value sanitization.** Strip or reject CRLF sequences in any value interpolated into HTTP headers. | P1 |

### 3.3 Code Pack Generation (MEDIUM)

**Surface:** `ocean build` compiles `.check.yaml` into standalone scripts (bash, Python, Go, etc.) via Handlebars templates.

**Vectors:**
- **T9: Script injection via check metadata.** If check `name`, `description`, or extracted field names contain shell metacharacters, generated bash scripts could execute arbitrary commands.
- **T10: Template injection.** If Handlebars templates are loaded from user-controllable paths, an attacker could inject malicious template logic.

**Mitigations:**

| ID | Mitigation | Priority |
|----|-----------|----------|
| M12 | **Shell escaping in templates.** All Handlebars helpers that emit values into shell contexts must apply proper escaping (single-quote wrapping, backslash escaping). Never emit raw interpolation into bash. | P0 |
| M13 | **Template source pinning.** Handlebars templates are bundled at compile time (embedded in binary or shipped in a known directory). Never load templates from user-controllable paths. | P1 |
| M14 | **Generated script linting.** CI runs shellcheck on generated bash, pylint on Python, etc. Syntactically invalid or suspicious output fails the build. | P2 |

### 3.4 Credential Management (CRITICAL)

**Surface:** API tokens with org-admin scopes are the most sensitive asset. They flow through environment variables → OCEAN runtime → HTTP requests → potentially into logs or error messages.

**Vectors:**
- **T11: Credential leakage in logs.** Tracing/logging could emit request headers or full URLs containing tokens.
- **T12: Credential leakage in error messages.** HTTP client errors may include the full request with Authorization header.
- **T13: Credential persistence in SQLite.** Evidence records could inadvertently store raw API responses containing tokens or PII.
- **T14: Credential exposure in generated code packs.** `ocean build` must not embed actual credential values in generated scripts.

**Mitigations:**

| ID | Mitigation | Priority |
|----|-----------|----------|
| M15 | **Credential redaction in logs.** Implement a tracing layer that redacts `Authorization` headers, token patterns (ghp_*, AKIA*, ssws_*), and any value from `credentials:` block. Use `secrecy::SecretString` for all credential values. | P0 |
| M16 | **Error message sanitization.** Wrap HTTP client errors to strip headers and credential values before surfacing to user or logs. | P0 |
| M17 | **No credentials in evidence store.** Evidence records store check results and metadata, never raw API responses. Strip `Authorization` and credential fields before SQLite insertion. | P0 |
| M18 | **Code packs use placeholders.** Generated scripts reference environment variables (`$GITHUB_TOKEN`), never literal credential values. | P0 |

### 3.5 REST API Server (`ocean serve`) (HIGH)

**Surface:** Network-accessible API providing programmatic access to observe, test, harden, and report operations.

**Vectors:**
- **T15: Unauthenticated access.** If `ocean serve` binds to 0.0.0.0 without authentication, any network peer can trigger checks or remediation.
- **T16: CSRF via browser.** If the API accepts requests from browser contexts without CSRF protection.
- **T17: Denial of service.** Unbounded concurrent check execution or expensive CEL evaluation.

**Mitigations:**

| ID | Mitigation | Priority |
|----|-----------|----------|
| M19 | **Bind to localhost by default.** `ocean serve` binds to `127.0.0.1` unless explicitly configured otherwise. | P0 |
| M20 | **API authentication.** Require a bearer token (generated on server start, displayed to user) for all API endpoints. | P1 |
| M21 | **Rate limiting.** Limit concurrent check executions and request rate on the API server. | P2 |
| M22 | **CORS restrictive default.** No CORS headers by default. If enabled, require explicit origin allowlist. | P1 |

### 3.6 Supply Chain (MEDIUM)

**Surface:** Cargo dependencies, community check contributions, CI/CD pipeline.

**Vectors:**
- **T18: Malicious Cargo crate.** A dependency (or transitive dependency) is compromised.
- **T19: CI tampering.** An attacker modifies `.check.yaml` files or Handlebars templates in a PR that bypasses review.

**Mitigations:**

| ID | Mitigation | Priority |
|----|-----------|----------|
| M23 | **`cargo audit` in CI.** Run `cargo audit` on every PR and release. Block merges with known vulnerabilities. | P0 |
| M24 | **Lockfile committed.** `Cargo.lock` is committed and reviewed for unexpected dependency changes. | P0 |
| M25 | **Check file review policy.** All `.check.yaml` PRs require CISO review (security-sensitive: they define HTTP requests and remediation actions). | P1 |
| M26 | **Dependency pinning.** Pin major versions of security-critical dependencies (serde_yaml, ureq, cel-interpreter, handlebars). | P1 |

### 3.7 Active Test Safety (HIGH)

**Surface:** Active tests (`type: active`) perform mutating operations against target systems (e.g., pushing test secrets, creating test resources).

**Vectors:**
- **T20: Active test against production.** User accidentally runs an active test against a production system instead of staging.
- **T21: Cleanup failure.** Active test creates artifacts (files, branches, users) but cleanup step fails, leaving residue.
- **T22: Safety classification bypass.** A check with `safety: destructive` is executed without sufficient warning.

**Mitigations:**

| ID | Mitigation | Priority |
|----|-----------|----------|
| M27 | **Safety gates in module executor.** Enforce the existing safety classification system: `safe` → auto, `observable` → warning, `reversible` → confirmation, `destructive` → explicit opt-in flag. | P0 |
| M28 | **Environment tagging.** Active tests with `environment: staging` should refuse to run unless the target is confirmed as non-production (via config or interactive prompt). | P1 |
| M29 | **Cleanup verification.** After active test cleanup steps, verify the cleanup succeeded (re-check for residual artifacts). Log failures prominently. | P1 |

## 4. Residual Risk

| Risk | Severity | Justification |
|------|----------|---------------|
| A sufficiently motivated attacker with write access to `~/.ocean/checks/` can exfiltrate credentials | Medium | Mitigated by M1 (URL allowlist), M3 (credential scoping), M6 (unverified check warning). Residual: local attacker with filesystem access has many other vectors. |
| CEL evaluation on adversarial input could have undiscovered edge cases | Low | CEL is a restricted expression language, not Turing-complete. The `cel-interpreter` crate is well-maintained. |
| Generated code packs could contain subtle logic errors that diverge from OCEAN runtime behavior | Medium | Mitigated by M14 (linting) and CI verification (generated packs are tested). Residual: semantic divergence between template output and interpreter logic. |
| Binary size increase from merge could affect deployment in constrained environments | Low | Acceptable tradeoff per ADR-001 analysis. |

## 5. Security Requirements for Acceptance Criteria

These must be incorporated into the spec and verified in QA:

1. **SR-1:** No HTTP request is made to a URL not on the source system's allowlist.
2. **SR-2:** Credentials are never logged, stored in evidence DB, or embedded in code packs.
3. **SR-3:** `ocean harden` defaults to `--dry-run`; mutating calls require `--confirm`.
4. **SR-4:** `ocean serve` binds to localhost by default.
5. **SR-5:** Active tests enforce safety gates based on `safety:` classification.
6. **SR-6:** All user-supplied inputs are validated before interpolation into URLs, headers, or bodies.
7. **SR-7:** `cargo audit` runs in CI with zero known vulnerabilities for releases.
8. **SR-8:** Community `.check.yaml` contributions require CISO review.

## 6. Implementation Priorities

**Before Phase 1 (foundation) ships:**
- M1, M2, M3 (URL allowlist, SSRF protection, credential scoping) — baked into the interpreter from day one
- M4 (remediation confirmation gate)
- M8, M9 (input sanitization, URL encoding)
- M15, M16, M17 (credential redaction)
- M18 (code pack placeholders)
- M23, M24 (cargo audit, lockfile)
- M27 (safety gates)

**Before Phase 2 (HTH feature absorption):**
- M5, M6, M7 (YAML limits, check hashing, path canonicalization)
- M10, M11 (CEL safety, header sanitization)
- M12, M13 (shell escaping, template pinning)
- M19, M20, M22 (API server security)
- M25, M26 (check review policy, dependency pinning)
- M28, M29 (environment tagging, cleanup verification)

**Before public release:**
- M14 (generated script linting)
- M21 (API rate limiting)
- Full penetration test of the check interpreter and code pack generator
