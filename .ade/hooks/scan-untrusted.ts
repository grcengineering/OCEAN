#!/bin/sh
# ade-scan-untrusted v1 -- managed by ADE Bootstrapper (injection-defense module).
# Runtime-free prompt-injection scanner shim (ISC-165): forwards text from
# stdin to the installed `ade` binary (`ade hook scan`), which scans it
# against the directive-injection patterns and prints a JSON verdict to stdout:
#   { "flagged": boolean, "matches": [{ "pattern": string, "excerpt": string }] }
# Exit code 1 when flagged, 0 when clean. No JS runtime needed -- vendor freely.
# Graceful no-op when `ade` is not on PATH: reports a clean verdict, exits 0.
if ! command -v ade >/dev/null 2>&1; then
  cat >/dev/null 2>&1
  printf '%s\n' '{"flagged":false,"matches":[]}'
  exit 0
fi
exec ade hook scan
