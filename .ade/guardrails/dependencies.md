---
id: dependencies
severity: high
applies_to: [all]
---

# Dependencies

Every dependency is third-party code running with your privileges.

DO:
- Prefer the standard library; add a dependency only when it earns its keep.
- Verify a package EXISTS and is the well-known one before adding it —
  AI-suggested names are untrusted (slopsquatting/typosquatting risk).
- Pin versions via the lockfile and commit it; upgrade deliberately.
- Run the project's vulnerability scanner after changing dependencies and
  fix HIGH/CRITICAL findings before proceeding.

DON'T:
- Don't add dependencies for trivial one-liners.
- Don't fetch code or install scripts from URLs at build/run time.
- Don't ignore or suppress vulnerability findings to get a build green —
  fix the code or upgrade the dependency.
- Don't use abandoned packages for security-critical functions.
