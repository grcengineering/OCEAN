# Testing Conventions

These conventions define what "tested" means in this repository.

## Test-first
- Write the failing test BEFORE the behavior change; the test defines done.
- A bug fix starts with a regression test that reproduces the bug.

## Meaningful assertions only
- Every test asserts an observable outcome that maps to an intended use case.
- Coverage padding is a defect: no assertion-free tests, no tests that only
  execute a line without verifying its effect, no contrived inputs whose only
  purpose is touching a branch.
- If reachable code cannot be covered by a meaningful test, treat the code as
  suspect — fix or delete it rather than padding around it.

## Coverage
- The coverage floor (95% line and function) is a hard gate; never lower
  it to make a change pass — write the real test instead.

## Integration over mocks
- Prefer exercising real components (temp dirs, real files, real subprocess
  contracts) when the real thing is cheap; mock only true external boundaries.
