# Quick Start Guide: Fresh OCEAN Session

This guide explains how to start a new Claude Code session for OCEAN development, whether continuing existing work or starting fresh.

## Option A: Continue Existing Work (Recommended)

All spec-kit artifacts are complete. To continue development:

### 1. Load Context

Tell Claude:
```
I'm continuing work on OCEAN. Please read:
1. CLAUDE.md for project overview
2. .specify/memory/constitution.md for principles
3. .specify/specs/ocean-core/tasks.md for next steps
```

### 2. Review Where We Left Off

All specification work is complete:
- [x] Constitution (v1.0.0)
- [x] Specification (7 user stories)
- [x] Implementation plan (6 phases)
- [x] Tasks (224 tasks)
- [ ] Implementation (not started)

### 3. Start Implementation

Begin with Phase 1, Task T001:
```
Start implementing OCEAN. Begin with Task T001: Initialize Go module.
```

---

## Option B: Start Fresh with Spec-Kit

If you want to redo the specification work using spec-kit commands properly:

### 1. Backup Existing Work

```bash
cd C:\Users\justi\Code\OCEAN
mkdir backup-2026-01-17
cp -r .specify backup-2026-01-17/
cp CLAUDE.md backup-2026-01-17/
cp -r docs backup-2026-01-17/
```

### 2. Clean Spec-Kit Artifacts

```bash
rm -rf .specify/specs
rm -rf .specify/memory
```

### 3. Re-Initialize Spec-Kit

From Git Bash (to avoid Windows encoding issues):
```bash
cd /c/Users/justi/Code/OCEAN
PYTHONIOENCODING=utf-8 uvx --from git+https://github.com/github/spec-kit.git specify init --here --ai claude --force
```

### 4. Use Slash Commands Manually

In Claude Code CLI, type these as slash commands (not as Skill invocations):

```
/speckit.constitution
```

Then provide the constitution content when prompted.

```
/speckit.specify
```

Then provide the specification content.

```
/speckit.plan
```

Then provide context for implementation planning.

```
/speckit.tasks
```

To generate tasks from the plan.

### 5. Note: Skills Don't Work

**DO NOT** try to invoke these programmatically:
```
# This WILL NOT work:
Skill("speckit.constitution", args)

# This WILL NOT work either:
Skill("speckit:constitution", args)
```

The spec-kit commands are installed as `.claude/commands/*.md` files which are meant for manual slash-command invocation, not Skill tool invocation.

---

## Option C: Reference Backup and Rewrite

If you want to redo spec-kit but use existing work as reference:

### 1. Copy Research to Clipboard

The key files to reference:
- `docs/SESSION-2026-01-17.md` - Full session log with research
- `.specify/specs/ocean-core/research.md` - All research findings
- `backup-2026-01-17/.specify/memory/constitution.md` - Existing constitution
- `backup-2026-01-17/.specify/specs/ocean-core/spec.md` - Existing spec

### 2. Tell Claude to Use as Reference

```
I'm redoing OCEAN spec-kit work. I have backup files from a previous session.
Please read docs/SESSION-2026-01-17.md for all research, then help me
recreate the spec-kit artifacts using the proper slash commands.
```

---

## Key Context to Provide in Any Session

### The Vision

OCEAN = "Metasploit for GRC" + "StatusPage for Compliance"

- Open-source CLI tool and Go library
- Collect evidence from APIs (Okta, AWS, GitHub, etc.)
- Normalize to OCSF-inspired schema
- Store with provenance for historical queries
- Calculate control effectiveness uptime (99.94% over 180 days)
- Power transparent compliance dashboards

### The Problem It Solves

SOC 2 has 3 flaws:
1. Vague control requirements
2. Point-in-time audits, not continuous
3. Static reports that become stale

OCEAN enables continuous compliance monitoring with historical proof.

### Technology Stack

- Go 1.22+
- SQLite (default), PostgreSQL (enterprise)
- JSON Schema for validation
- Apache 2.0 license

### 8 Core Principles

1. Evidence-First Architecture
2. OCSF-Inspired Schema Design
3. Metasploit-Style Extensibility
4. Cross-Platform Portability
5. Control-Centric Organization
6. Continuous Monitoring Native
7. Radical Transparency
8. Security & Privacy by Design

---

## File Reference

| File | Purpose |
|------|---------|
| `CLAUDE.md` | Quick project context for Claude |
| `docs/SESSION-2026-01-17.md` | Full session log with issues |
| `docs/QUICKSTART-FRESH-SESSION.md` | This file |
| `.specify/memory/constitution.md` | Core principles |
| `.specify/specs/ocean-core/spec.md` | Full specification |
| `.specify/specs/ocean-core/plan.md` | Implementation plan |
| `.specify/specs/ocean-core/tasks.md` | Detailed tasks |
| `.specify/specs/ocean-core/research.md` | Research notes |

---

## Spec-Kit Issues Summary

### What Went Wrong

1. `Skill("speckit.constitution")` doesn't work - commands are in `.claude/commands/`, not registered as skills
2. Windows console has Unicode issues with spec-kit banner - use Git Bash
3. `--tool` flag doesn't exist - use `--ai` instead

### What Worked

1. Running spec-kit init from Git Bash with `PYTHONIOENCODING=utf-8`
2. Reading the command templates and writing artifacts directly
3. All artifacts conform to template structure

### Recommendation

For now, write spec artifacts directly following the templates. The slash commands may work in interactive CLI but the Skill tool invocation does not work for spec-kit commands.
