---
id: authn-authz
severity: critical
applies_to: [all]
---

# Authentication & Authorization

Every non-public operation checks WHO is calling and WHETHER they may.

DO:
- Enforce authentication and authorization on the server for every request;
  deny by default when no rule matches.
- Perform object-level checks: verify the caller may access the specific
  resource id in the request (prevent IDOR/BOLA).
- Use the platform's vetted auth framework and session management; store
  session tokens in HttpOnly, Secure cookies where applicable.
- Derive privileged fields (user id, role, tenant) from the verified session,
  never from the request body.
- Validate JWTs fully: signature, algorithm allowlist, expiry, issuer,
  and audience.

DON'T:
- Don't roll your own authentication, session, or password storage; use
  argon2/bcrypt/scrypt via a maintained library when you must hash passwords.
- Don't rely on hiding UI elements or "unguessable" URLs as access control.
- Don't accept `alg: none` or client-supplied role/tenant/id claims.
- Don't add authentication bypasses for tests or debugging into shipped code.
