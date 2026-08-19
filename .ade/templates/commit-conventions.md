# Commit Conventions

Every commit in this repository follows these rules.

## Format
- Conventional-commit style: `type(scope): subject` with types
  `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`, `build`.
- Subject is imperative mood ("add", not "added" or "adds") and at most 72 characters.
- Body explains WHY the change was made — the diff already shows what.

## Scope
- One logical change per commit; split unrelated changes into separate commits.
- Never mix a refactor with a behavior change in the same commit.

## Never commit
- Secrets, tokens, credentials, or private keys of any kind.
- Generated artifacts, build output, or local tooling state that belongs in
  `.gitignore`.
- Commented-out code or debugging leftovers.
