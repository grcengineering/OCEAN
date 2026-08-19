---
id: injection
severity: critical
applies_to: [all]
---

# Injection (SQL / Command / Path / XSS)

Never build executable syntax by string concatenation with untrusted data.

DO:
- SQL: use parameterized queries / prepared statements for EVERY query;
  identifiers that must vary come from a hardcoded allowlist.
- Commands: use argv-array process APIs (execFile/spawn with arg lists);
  if a shell is truly unavoidable, allowlist-validate every argument first.
- Paths: resolve to an absolute path, then verify it is inside the intended
  root directory before reading or writing; reject on failure.
- XSS: rely on the framework's contextual auto-escaping; sanitize any
  unavoidable raw-HTML sink with a maintained sanitizer library.
- Set a restrictive Content-Security-Policy on web surfaces.

DON'T:
- Don't interpolate user input into SQL, shell strings, eval, or templates —
  no exceptions, including "internal" or "trusted" values.
- Don't strip ../ sequences and call it path validation; check containment
  after full resolution.
- Don't use innerHTML/dangerouslySetInnerHTML with any user-influenced value.
- Don't disable framework escaping to "fix" rendering problems.
