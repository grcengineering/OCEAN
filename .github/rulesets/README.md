# Repository rulesets

`main-branch-protection.json` is the ruleset this repository's supply-chain policy
expects on the default branch. It is kept here because a ruleset lives in GitHub's
settings, not in the tree — so without a checked-in copy there is nothing to review,
diff, or restore.

## Current state vs. this file

`sscsb verify branch-protection` reports what is actually live. As of 2026-09-12 the
live ruleset (id `14413947`, "Branch protection", active, targeting `~DEFAULT_BRANCH`)
carried only `deletion` and `non_fast_forward`, and `sscsb verify` failed with
`MISSING required pull requests`, `MISSING required signed commits`, and
`MISSING required status checks`. This file adds exactly those three rules.

Note that `sscsb harden branch-protection` cannot write them here: it looks for a
ruleset whose `ref_name.include` names the branch literally, and this one targets the
`~DEFAULT_BRANCH` alias, so the planner reports "no ruleset targets this branch —
skipped" and changes nothing.

| Rule | Why |
|------|-----|
| `pull_request` (0 approvals required) | Nothing reaches `main` without a pull request, so every change has a reviewable record and CI runs against it before merge. 0 approvals is the solo-safe setting — a maintainer cannot approve their own PR, so requiring 1 would deadlock a single-maintainer repo. Raise it to 1 as soon as there is a second maintainer. |
| `required_signatures` | Every commit that lands on `main` is cryptographically attributable. |
| `required_status_checks` | The 13 checks listed must pass before merge. They were taken from checks that actually ran on a real pull request (`34117a7`), not guessed. `Behavioral Analysis (Socket.dev)` is deliberately excluded because it is conditional and reports `skipped`; `Test (nightly)` because a nightly-toolchain regression is not a reason to block a merge. |

`allowed_merge_methods` is `squash` and `rebase`, and that is not cosmetic. With
`required_signatures` active, GitHub signs the squashed or rebased commit with its
web-flow key. A merge-commit merge instead lands the PR's own commits on `main`
unchanged, so an unsigned commit from a contributor would be rejected at merge time.
Every commit currently on `main` is single-parent, so squash is already the norm here.

## Applying it

Either import it in the UI — **Settings → Rules → Rulesets → New ruleset → Import a
ruleset** — or update the existing ruleset in place:

```sh
gh api -X PUT repos/grcengineering/OCEAN/rulesets/14413947 \
  --input .github/rulesets/main-branch-protection.json
```

Then confirm against the tool rather than the UI:

```sh
sscsb verify branch-protection
```

## Rolling it back

Re-import, or send a body whose `rules` array holds only `deletion` and
`non_fast_forward`. Rulesets are versioned by GitHub and nothing here is destructive.
