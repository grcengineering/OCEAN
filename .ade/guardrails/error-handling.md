---
id: error-handling
severity: medium
applies_to: [all]
---

# Error Handling & Logging

Fail closed, tell the user little, tell the operator enough.

DO:
- Fail closed: on unexpected errors in a security decision, deny.
- Return generic error messages to callers; log the detailed cause
  server-side with a correlation id.
- Handle every error path explicitly — no empty catch blocks; either
  recover meaningfully or propagate.
- Log security-relevant events (authn failures, authz denials, validation
  rejects) at a consistent level for monitoring.

DON'T:
- Don't leak stack traces, file paths, SQL, or dependency versions in
  responses to callers.
- Don't log secrets, session tokens, or full request bodies containing
  personal data (redact first).
- Don't swallow exceptions to make tests or demos pass.
- Don't use error messages to enumerate state (e.g. "user exists but wrong
  password") — keep authn errors uniform.
