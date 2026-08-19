---
id: input-validation
severity: high
applies_to: [all]
---

# Input Validation

All data crossing a trust boundary (HTTP requests, CLI args, file contents,
environment, IPC, LLM output) is untrusted until validated.

DO:
- Validate at the boundary, immediately on receipt, before any other use.
- Use allowlists (known-good shapes) — schema validation, strict enums, typed parsers.
- Enforce length, range, and type limits on every field; reject, don't truncate.
- Canonicalize (decode, normalize unicode/paths) BEFORE validating, never after.
- Treat deserialized data (JSON, YAML, pickle-like formats) as untrusted input.

DON'T:
- Don't use denylists or regex "bad character" filters as the primary control.
- Don't validate on the client only — server-side validation is the control.
- Don't pass unvalidated input into interpreters, templates, or file APIs
  (see injection.md).
- Don't accept unbounded collections or payloads; cap sizes explicitly.
