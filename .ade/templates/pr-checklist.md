# PR Checklist

Work through every item before requesting review. An unchecked item is a
blocker, not a suggestion.

## Tests
- [ ] Tests added or updated for every behavior change in this PR.
- [ ] Full test suite passes locally — paste the command and exit code in the PR description.
- [ ] Coverage floor met (95% line and function minimum) — the CI gate is not lowered.

## Security
- [ ] Security review done on every touched surface (inputs, auth, subprocess, file, and network boundaries).
- [ ] No secrets, tokens, or credentials in code, config, tests, or fixtures.
- [ ] No scanner findings suppressed — every true positive is fixed at the code level.

## Hygiene
- [ ] Docs updated for any changed behavior, options, or public interfaces.
- [ ] No generated artifacts, lockfile noise, or unrelated changes bundled in.
- [ ] PR description states WHAT changed, WHY, and how it was verified.
