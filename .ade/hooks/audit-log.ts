#!/bin/sh
# ADE audit hook — Claude Code PostToolUse.
# Installed by ADE Bootstrapper (observability module). Reads the PostToolUse
# hook event JSON from stdin and appends one hash-chained entry to
# .ade/audit/log.jsonl via the installed `ade` binary. Never blocks the
# harness: exits 0 even when `ade` is not on PATH.
if command -v ade >/dev/null 2>&1; then
  exec ade hook append --dir "."
fi
cat >/dev/null 2>&1
exit 0
