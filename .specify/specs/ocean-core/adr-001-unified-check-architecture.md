# ADR-001: Unified Check Architecture — OCEAN Absorbs HTH

**Status:** Accepted
**Date:** 2026-03-28
**Authors:** Justin Pagano
**Deciders:** Justin Pagano

## Context

OCEAN ("Metasploit for GRC") and HTH CLI ("How To Harden") both perform security checks against the same APIs, asserting the same conditions, but are implemented independently — OCEAN in Rust (observers/testers), HTH in Rust + bash scripts + YAML control definitions.

A coverage gap analysis (2026-03-28) found:
- **OCEAN**: 24 GitHub observers, 6 GitHub testers
- **HTH**: 40 GitHub API scripts, 41 YAML control definitions
- **~38 checks exist in only one tool**, creating a parity problem that grows with every new check

The core issue: identical check logic is written twice with no mechanism to detect or prevent drift.

### Key Constraints

1. **Solo maintainer** — Justin maintains both tools; two repos, two CIs, two release cycles doubles coordination cost
2. **Open source tool** — no commercial/product positioning considerations apply
3. **No attestation in OCEAN** — cryptographic attestation (DSSE, signing) is handled by Corsair (Ayoub Fandi's project); OCEAN pipes outputs to Corsair
4. **No trust boundary concern** — without attestation signing, there is no security reason to separate observation from remediation

### What Led to This Decision

A Council debate (4 agents, 3 rounds) and Red Team parallel analysis (8 agents) were conducted. The Council voted 3-1 to merge, with the sole dissenter (Security perspective) objecting on trust boundary grounds — that a binary signing attestations should not also execute remediation. When attestation was removed from OCEAN's scope (delegated to Corsair), the objection became moot and the decision became unanimous.

The Red Team's strongest counterarguments — identity dilution, scope creep, and HTH users forking — were evaluated against the open-source-only context and found to be non-blocking. The maintenance burden of two tools for a solo maintainer is the dominant practical constraint.

## Decision

### Merge OCEAN and HTH into One CLI

OCEAN becomes the single unified tool. HTH's capabilities (remediation, code pack generation, fleet operations, compliance reporting, profile tiers) are absorbed as subcommands and module types within OCEAN.

### The .check.yaml Meta-Code Format

Checks are defined in structured YAML (`.check.yaml`) — the single source of truth for all check logic. OCEAN interprets them at runtime. OCEAN's build system compiles them into standalone code packs.

```
                    ┌─────────────────────┐
                    │   check.yaml        │  ← Community authors write THIS
                    │   (meta-code)       │
                    └──────────┬──────────┘
                               │
                  ┌────────────┼────────────┐
                  │                         │
             ┌────▼────┐             ┌──────▼─────┐
             │  OCEAN   │             │ ocean build │
             │ runtime  │             │  (codegen)  │
             └────┬────┘             └──────┬─────┘
                  │                         │
        ┌─────────┼──────────┐    ┌─────────┼──────────┐
        │         │          │    │         │          │
    Evidence  Report   Remediate  bash    Python    Rego  ...
    (OCSF)    (CIS)    (API/TF)  +curl    SDK      OPA
```

One tool. One runtime. N code packs. Community-contributed. Metasploit-style drop-in extensibility.

### OCEAN Subcommand Structure

```
ocean observe <check>              Observe evidence via passive check
ocean test <check>                 Run active test with safety gates
ocean harden <check>               Remediate failing controls (API or Terraform)
ocean scan <source>                Run all checks for a source system
ocean evaluate <control>           Evaluate control against evidence (CEL)
ocean report --framework soc2      Compliance report mapped to frameworks
ocean build --target api-script    Generate standalone code packs
ocean modules list                 List available checks
ocean modules validate <id>        Validate check definition
ocean history --control <id>       Query control evaluation history
ocean schedule add                 Cron-based scheduling
ocean serve                        REST API server
```

### Module Types

| Type | Purpose | Example |
|---|---|---|
| **Observer** (passive) | Query API, observe configuration state | Check if MFA is enforced |
| **Tester** (active) | Attempt what controls should prevent | Push a test secret to verify push protection |
| **Remediator** | Fix failing controls via API or Terraform | Enable MFA enforcement via PATCH |
| **Reporter** | Generate compliance reports | SOC2, NIST, ISO27001, PCI DSS, STIG mapping |

All four types can be expressed in `.check.yaml`. The `remediation:` block in a check file defines the Remediator. The `references:` block drives the Reporter.

### The Check File Format

Prior art: **Nuclei** (projectdiscovery) validated this model for vulnerability scanning — YAML templates defining HTTP requests + matchers + extractors, with 9,000+ community templates. This is the "Nuclei for GRC" equivalent.

#### Passive Check Example

```yaml
# checks/github/GH-1.01-org-mfa.check.yaml

id: GH-1.01
name: Enforce 2FA for Organization Members
description: |
  Verifies that the GitHub organization requires two-factor authentication
  for all members and identifies any non-compliant users.
author: grc-engineering
version: "1.0"
source: github
profile: L1
tags: [authentication, mfa, organization]

references:
  cis: "1.1"
  nist: ["IA-2(1)", "IA-2(2)"]
  soc2: "CC6.1"
  iso27001: "A.9.4.2"

credentials:
  GITHUB_TOKEN:
    type: api_token
    scopes: [admin:org, read:org]
    required: true

inputs:
  org:
    description: GitHub organization name
    env: GITHUB_ORG
    required: true

steps:
  - id: get_org_settings
    action: api_call
    request:
      method: GET
      url: "https://api.github.com/orgs/{{org}}"
      headers:
        Authorization: "Bearer {{GITHUB_TOKEN}}"
        Accept: application/vnd.github+json
    extract:
      mfa_enforced: $.two_factor_requirement_enabled
      default_permission: $.default_repository_permission
      org_name: $.login

  - id: get_non_compliant_members
    action: api_call
    request:
      method: GET
      url: "https://api.github.com/orgs/{{org}}/members?filter=2fa_disabled"
      headers:
        Authorization: "Bearer {{GITHUB_TOKEN}}"
        Accept: application/vnd.github+json
      paginate: true
    extract:
      non_compliant_users: $[*].login
      non_compliant_count: $length

assertions:
  - id: mfa_enforcement
    expr: "mfa_enforced == true"
    severity: critical
    title: Organization MFA Enforcement
    pass_message: "MFA is enforced for all {{org_name}} members"
    fail_message: "MFA is NOT enforced for organization {{org_name}}"
    finding:
      description: |
        Two-factor authentication is not required for organization members.
        Any member can authenticate with only a password, making accounts
        vulnerable to credential stuffing and phishing attacks.

  - id: member_compliance
    expr: "non_compliant_count == 0"
    severity: high
    title: Member 2FA Compliance
    pass_message: "All members have 2FA enabled"
    fail_message: "{{non_compliant_count}} members lack 2FA: {{non_compliant_users}}"
    finding:
      description: |
        Members without 2FA represent a credential compromise risk.
        These accounts should be removed or required to enable 2FA.

remediation:
  description: |
    Enable 2FA requirement in Organization Settings → Authentication security.
    Non-compliant members will be removed from the organization until they
    enable 2FA on their accounts.
  steps:
    - "Navigate to github.com/orgs/{org}/settings/security"
    - "Check 'Require two-factor authentication for everyone'"
    - "Click Save"
  api:
    method: PATCH
    url: "https://api.github.com/orgs/{{org}}"
    body:
      two_factor_requirement_enabled: true
  cli:
    command: "gh api orgs/{{org}} -X PATCH -f two_factor_requirement_enabled=true"
  terraform:
    resources:
      - type: github_organization_settings
        name: security
        config:
          two_factor_requirement: true
```

#### Active Check Example

```yaml
# checks/github/GH-TEST-01-secret-push.check.yaml

id: GH-TEST-01
name: Secret Push Protection Test
description: |
  Actively attempts to push a known test secret to verify that
  GitHub's push protection blocks it.
author: grc-engineering
version: "1.0"
source: github
type: active
safety: observable
environment: staging
profile: L1
tags: [secret-scanning, push-protection, active-test]

references:
  cis: "2.1"
  nist: ["IA-5(7)", "SC-28"]

credentials:
  GITHUB_TOKEN:
    type: api_token
    scopes: [repo]
    required: true

inputs:
  owner:
    description: Repository owner
    env: GITHUB_OWNER
    required: true
  repo:
    description: Repository name
    env: GITHUB_REPO
    required: true

pre_flight:
  - "Verify GitHub token has write access to repository"
  - "Verify repository is a test/staging repository"
  - "This test creates audit trail entries in GitHub"

steps:
  - id: attempt_push
    action: api_call
    request:
      method: PUT
      url: "https://api.github.com/repos/{{owner}}/{{repo}}/contents/ocean-test-secret.txt"
      headers:
        Authorization: "Bearer {{GITHUB_TOKEN}}"
        Accept: application/vnd.github+json
      body:
        message: "ocean: secret push protection test (will be cleaned up)"
        content: "{{base64('TEST_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01')}}"
    extract:
      push_status: $status_code
      push_sha: $.content.sha
    on_error:
      422: continue

  - id: cleanup
    action: api_call
    when: "push_status != 422"
    request:
      method: DELETE
      url: "https://api.github.com/repos/{{owner}}/{{repo}}/contents/ocean-test-secret.txt"
      headers:
        Authorization: "Bearer {{GITHUB_TOKEN}}"
        Accept: application/vnd.github+json
      body:
        message: "ocean: cleanup test file"
        sha: "{{push_sha}}"

assertions:
  - id: push_blocked
    expr: "push_status == 422"
    severity: critical
    title: Secret Push Protection
    pass_message: "Push protection correctly blocked the test secret"
    fail_message: "Secret was pushed without being blocked — push protection may be disabled"

remediation:
  description: |
    Enable push protection in repository settings → Code security and analysis.
  steps:
    - "Navigate to github.com/{{owner}}/{{repo}}/settings/security_analysis"
    - "Enable 'Secret scanning' and 'Push protection'"
```

### Format Design Principles

1. **`steps` are declarative API calls, not code.** Every step is: make a request, extract fields with JSONPath. Covers ~90% of checks. Structured enough to compile to any language, readable enough for humans to modify.

2. **`assertions` use CEL expressions.** OCEAN already has a CEL engine. CEL provides `field == value`, `count > 0`, `list.exists(x, x.role == "admin")` without being a full programming language.

3. **`extract` uses JSONPath.** Universal — every language has a library. Maps API responses to named variables.

4. **`remediation` defines how to fix failing controls.** Includes human steps, API remediation, CLI commands, and Terraform resources. Used by `ocean harden` and code pack generation.

5. **`inputs` and `credentials` are the configuration contract.** The runtime knows what to prompt for.

6. **Active checks** use `when`, `on_error`, `type: active`, `safety`, `environment`, and `pre_flight` for imperative flow control. Still declarative enough to compile, but expressive enough for real active tests.

7. **Template variables** (`{{org}}`, `{{GITHUB_TOKEN}}`) are resolved at runtime from inputs, credentials, and extracted values.

### Code Pack Generation

`ocean build` compiles `.check.yaml` files into standalone, human-readable scripts. Generated scripts are checked into the repo so users can browse, audit, and run them without installing OCEAN.

```
ocean build [options]

  --target <target>      Output format: api-script, gh-cli, python-sdk,
                         go-sdk, opa-rego, terraform, sigma-rule
  --source <glob>        Check files to compile (default: checks/**/*.check.yaml)
  --output <dir>         Output directory (default: packs/<target>/)
  --validate             Validate check files without generating
  --diff                 Show what would change without writing
```

Supported targets:

| Target | Output | Use Case |
|---|---|---|
| `api-script` | Bash + curl + jq | Universal, no dependencies beyond curl/jq |
| `gh-cli` | Bash + gh CLI | GitHub CLI users |
| `python-sdk` | Python + PyGithub/boto3 | Python automation |
| `go-sdk` | Go + go-github/aws-sdk | Go automation |
| `opa-rego` | OPA Rego policies | Policy-as-code pipelines |
| `terraform` | HCL check blocks | Terraform validation |
| `sigma-rule` | Sigma YAML | SIEM drift/threat detection |

CI ensures code packs stay in sync:

```yaml
- name: Validate check files
  run: ocean build --validate

- name: Verify code packs are up to date
  run: |
    ocean build --target all
    git diff --exit-code packs/ || {
      echo "Code packs are out of date. Run 'ocean build --target all' and commit."
      exit 1
    }
```

### How OCEAN Loads Checks

OCEAN interprets `.check.yaml` files at runtime. The Rust runtime parses YAML, makes HTTP calls, evaluates JSONPath extractions and CEL assertions, and wraps results in Evidence.

```rust
// ocean/src/module/check_loader.rs

pub fn load_checks(registry: &Registry, dir: &Path) -> Result<()> {
    for entry in glob(&dir.join("**/*.check.yaml")) {
        let check_def: CheckDefinition = serde_yaml::from_reader(File::open(entry)?)?;

        match check_def.check_type() {
            CheckType::Passive => {
                let observer = YamlObserver::new(check_def);
                registry.register_observer(Arc::new(observer));
            }
            CheckType::Active => {
                let tester = YamlTester::new(check_def);
                registry.register_tester(Arc::new(tester));
            }
        }
    }
    Ok(())
}
```

**Load paths** (Metasploit-style drop-in):
```
1. Bundled:   checks/ directory shipped with OCEAN
2. User:      ~/.ocean/checks/*.check.yaml       ← drop-in, like ~/.msf4/modules/
3. Custom:    --checks-dir /path/to/custom/       ← like Metasploit's loadpath
4. Native:    compiled Rust modules (escape hatch for complex logic)
```

### The Native Escape Hatch (10% of Checks)

Some active checks need imperative logic too complex for declarative YAML. For these, the YAML file retains all metadata but delegates execution to compiled Rust:

```yaml
id: GH-TEST-99
name: Complex Active Test
type: active
safety: reversible
implementation: native
native_module: github_complex

# Metadata still in YAML (references, credentials, inputs, remediation)
references:
  nist: [...]
credentials:
  GITHUB_TOKEN: { type: api_token, required: true }
remediation:
  description: ...
```

Code packs cannot be generated for native checks (`ocean build` emits a stub noting "requires OCEAN CLI").

### HTH Features Absorbed into OCEAN

| HTH Feature | OCEAN Subcommand | Notes |
|---|---|---|
| `hth scan` | `ocean scan` / `ocean observe` | Same check execution, OCEAN output format |
| `hth remediate` | `ocean harden` | API-based and Terraform-based remediation |
| `hth report` | `ocean report --framework` | SOC2, NIST, ISO27001, PCI DSS, DISA STIG |
| `hth build` | `ocean build --target` | Code pack generation |
| `hth validate` | `ocean modules validate` | Check YAML schema validation |
| `hth analyze` | `ocean analyze` | SaaS stack composition analysis |
| `hth init` | `ocean init` | Config file generation |
| `hth list` | `ocean modules list` | List checks, sources, frameworks, tags |
| Profile tiers (L1/L2/L3) | `--profile L1\|L2\|L3` | Cumulative hardening levels |
| SARIF output | `--format sarif` | GitHub Security tab, IDE integration |
| CSV output | `--format csv` | Spreadsheet/BI tools |
| Multi-repo fleet ops | `ocean harden --fleet` | Apply remediation across all repos in org |
| Tag/severity filtering | `--tags`, `--severity` | Filter checks by metadata |
| Dry-run mode | `--dry-run` | Preview changes without executing |
| Scan result caching | `ocean report --scan-file` | Offline compliance reports |

### Output Formats

OCEAN supports multiple output formats across subcommands:

| Format | Flag | Use Case |
|---|---|---|
| `table` | `--format table` | Human-readable CLI output (default) |
| `json` | `--format json` | Machine parsing, CI/CD, piping to Corsair |
| `csv` | `--format csv` | Spreadsheets, BI tools |
| `sarif` | `--format sarif` | GitHub Security tab, IDE integration |

### Corsair Integration

OCEAN produces structured evidence output. Cryptographic attestation (DSSE, Ed25519 signing, in-toto envelopes) is handled by **Corsair** (Ayoub Fandi's project):

```bash
# OCEAN collects evidence, Corsair signs it
ocean observe github.org_mfa --format json | corsair attest --key signing.key
```

OCEAN's output format is designed to be Corsair-consumable. The `ed25519-dalek` and DSSE-related dependencies will be removed from OCEAN.

### Community Contribution Flow

```
1. Author writes my-check.check.yaml
2. Author tests locally:
   - ocean observe my-check --org testorg           # Run the check
   - ocean harden my-check --org testorg --dry-run   # Preview remediation
   - ocean build --target api-script my-check.yaml   # Generate bash script
   - bash packs/api-script/my-check.sh               # Script runs standalone
3. Author submits PR to OCEAN repo
4. CI validates:
   - YAML schema validation (all required fields present)
   - CEL expression parsing (assertions are valid)
   - Code pack generation (all targets build cleanly)
   - Generated scripts are syntactically valid
5. Merged → available in OCEAN on next release
```

### Repository Structure (Post-Merge)

```
ocean/                                     # Single repo
├── Cargo.toml                             # Workspace (or single crate)
├── src/
│   ├── main.rs                            # CLI entry point
│   ├── cli/                               # Subcommands (observe, test, harden, scan,
│   │                                      #   report, build, evaluate, schedule, serve)
│   ├── evidence/                           # OCSF-inspired evidence types
│   ├── module/                             # Module traits, registry, executor, safety
│   ├── eval/                               # CEL evaluation engine
│   ├── control/                            # Control definitions, composite controls
│   ├── check/                              # .check.yaml loader and YAML interpreter
│   │   ├── loader.rs                       # File discovery and registration
│   │   ├── interpreter.rs                  # YAML step execution (HTTP, JSONPath, CEL)
│   │   └── definition.rs                   # CheckDefinition serde types
│   ├── harden/                             # Remediation engine (API + Terraform)
│   ├── report/                             # Compliance reporting (SOC2, NIST, ISO, etc.)
│   ├── codegen/                            # Code pack generation (ocean build)
│   │   ├── mod.rs
│   │   └── templates/                      # Handlebars templates per target
│   ├── storage/                            # SQLite storage
│   ├── scheduler/                          # Cron scheduling
│   ├── api/                                # REST API (axum)
│   └── modules/                            # Built-in native modules
│       ├── observers/                      # Compiled observers (escape hatch)
│       └── testers/                        # Compiled testers (escape hatch)
├── checks/                                 # .check.yaml definitions (the source of truth)
│   ├── github/
│   ├── okta/
│   ├── aws/
│   └── azure/
├── packs/                                  # Generated code packs (committed, CI-verified)
│   ├── api-script/
│   ├── gh-cli/
│   ├── python-sdk/
│   ├── opa-rego/
│   ├── terraform/
│   └── sigma-rule/
├── controls/                               # YAML control definitions (CEL evaluation)
├── schemas/                                # JSON Schema definitions
└── docs/
```

## Alternatives Considered

### Alternative 1: Keep Separate, Share .check.yaml

Two repos, two binaries, shared check definitions. Each tool has its own YAML interpreter.

**Rejected because:** Solo maintainer cannot sustain two CIs, two release cycles, two dependency trees. Council + Red Team analysis confirmed maintenance burden is the dominant constraint. No trust boundary justifies separation (attestation handled by Corsair).

### Alternative 2: Shared YAML Registry with Implementation Pointers

A registry tracking which checks are implemented in which tool.

**Rejected because:** Tracks parity but doesn't eliminate duplication. Two implementations still drift.

### Alternative 3: Shared Compiled Rust Crate (Two Binaries, Shared Logic)

All check logic in `grc-controls-checks`, both tools link against it.

**Rejected because:** Doesn't eliminate the two-binary coordination cost. Cannot generate standalone code packs from compiled code. Community contributors must write Rust.

### Alternative 4: Cargo Workspace, Two Thin Binaries, One Repo

One repo, one CI, but two binary targets (`ocean` and `hth`).

**Rejected because:** Without attestation in OCEAN, there is no trust boundary that requires process-level separation. Two binaries add configuration complexity (which tool do I use for X?) with zero security benefit. The council's security dissenter conceded once attestation was removed.

## Consequences

### Positive
- **Zero duplication**: Check logic authored once in YAML, consumed everywhere
- **Community extensibility**: Anyone can write a `.check.yaml` — no compilation, no Rust knowledge
- **Standalone scripts**: Code packs run independently without OCEAN installed
- **Metasploit-style drop-in**: `~/.ocean/checks/` for user-authored checks
- **N output formats**: One check → bash, Python, Go, Rego, Terraform, Sigma
- **Inspectable**: Every check is human-readable YAML, every code pack is readable source
- **Single maintenance surface**: One repo, one CI, one release, one binary
- **Full-cycle workflow**: Observe → test → evaluate → harden → report in one tool
- **Corsair pipeline**: Clean JSON output format designed for downstream attestation

### Negative
- **Expression language ceiling**: CEL + JSONPath can't express all logic; ~10% need native escape hatch
- **Runtime overhead**: YAML parsing + CEL evaluation is slower than compiled Rust (acceptable for API-bound checks)
- **Codegen maintenance**: Each target language template requires ongoing maintenance
- **Schema evolution**: `.check.yaml` format must be backward-compatible once community adopts it
- **Binary size**: Merged binary is larger than either individual tool
- **HTH migration**: Existing HTH users need to switch to `ocean` CLI

### Neutral
- OCEAN's existing compiled modules (Observer/Tester traits) continue to work alongside YAML checks
- Framework reference mappings (CIS, NIST, SOC2) move into check files — single source of truth
- OCEAN's OCSF evidence envelope, CEL evaluation engine untouched — they consume check results
- HTH's howtoharden.com guides remain valid — they reference check IDs, not CLI commands

## Migration Strategy

1. **Define the `.check.yaml` JSON Schema** — formalize the format with validation
2. **Build the YAML check loader** — `YamlObserver` and `YamlTester` interpreting check files at runtime
3. **Port GH-1.01** (Org MFA) as proof of concept — verify runtime execution and code pack generation
4. **Add `ocean harden` subcommand** — remediation engine (API + Terraform) from HTH
5. **Add `ocean report` subcommand** — compliance reporting with framework mappings from HTH
6. **Add `ocean build` subcommand** — code pack generation (api-script and gh-cli first)
7. **Port remaining GitHub checks** — convert OCEAN observers and HTH scripts to `.check.yaml`
8. **Add reporting formats** — SARIF, CSV output alongside JSON and table
9. **Add fleet operations** — multi-repo remediation from HTH
10. **Add remaining code pack targets** — Python SDK, OPA Rego, Terraform, Sigma rules
11. **Remove attestation code** — drop DSSE/Ed25519 dependencies, design Corsair output format
12. **Port Okta, AWS, Azure checks** — same pattern as GitHub
13. **Publish check authoring guide** — open community contributions

## Metasploit Lessons Applied

| Metasploit Pattern | OCEAN Adaptation |
|---|---|
| Info hash as universal descriptor | `.check.yaml` metadata block (id, name, references, credentials, inputs) |
| Module types as behavioral contracts | Observer (passive), Tester (active), Remediator, Reporter |
| References as first-class metadata | `references:` section with CIS, NIST, SOC2, ISO27001, MITRE |
| Mixins for shared protocol behavior | `grc-controls-apis` crate (GitHub client, Okta client, AWS signer) |
| `check()` with standardized codes | `assertions:` with CEL expressions producing Pass/Fail/Warning/Error |
| Safety/ranking system | `safety:` (safe/observable/reversible/destructive) + `profile:` (L1/L2/L3) |
| Drop-in module extensibility | `~/.ocean/checks/` directory, `--checks-dir` flag |
| Convention-based discovery | `checks/{source_system}/` directory structure |
| One tool, many module types | Single `ocean` binary with observe/test/harden/report/build subcommands |

## What We Explicitly Did NOT Adopt from Metasploit

| Metasploit Pattern | Why Not |
|---|---|
| Ruby `eval` dynamic loading | YAML interpretation is safer; native escape hatch for complex logic |
| 7 module types | GRC needs 4 (observer, tester, remediator, reporter) |
| DataStore global mutation | Immutable inputs/credentials from environment + config |
| Payload/encoder/NOP concepts | Not applicable to compliance checking |
| 5000+ module scale optimizations | Target ~200 curated checks; optimize if needed later |
| Interactive console (msfconsole) | CLI-first; REST API for programmatic access |

## Future Considerations

### WASM for Native Escape Hatch

When the native escape hatch (`implementation: native`) proves limiting, complex checks could compile to WASM instead of requiring Rust linkage:

```
Now:     native checks → compiled Rust in ocean binary
Later:   native checks → .wasm modules in ~/.ocean/checks/
```

### Check Marketplace

Once community adoption is established, a check marketplace (similar to Nuclei Templates) could provide:
- Curated, reviewed check collections per compliance framework
- Organization-specific check packs
- Version pinning and dependency management between checks
