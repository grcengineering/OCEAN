---
id: secrets-handling
severity: critical
applies_to: [all]
---

# Secrets Handling

Generated code must never contain, log, or transmit secret material.

DO:
- Read secrets from the environment or a secret manager at the point of use.
- Reference secrets by NAME in code, config templates, and docs (e.g.
  `API_KEY`), never by value.
- Redact known-sensitive fields before logging or serializing objects.
- Add secret-bearing files (.env, *.pem, *.key) to .gitignore before
  creating them.

DON'T:
- Don't hardcode API keys, tokens, passwords, or private keys — not in code,
  tests, fixtures, examples, or comments.
- Don't echo environment variables that look like credentials
  (`*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`).
- Don't write secrets into error messages, debug output, or URLs.
- Don't invent placeholder secrets that look real; use obvious placeholders
  like `<YOUR_API_KEY>`.
