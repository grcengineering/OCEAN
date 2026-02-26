# Quickstart: OCEAN Core

> **Note**: This is a design-phase quickstart guide. These commands represent the intended CLI interface for OCEAN once implemented. They do not work today.

## Prerequisites

- Go 1.22+ (for building from source)
- API credentials for target systems (Okta, AWS, GitHub, etc.)

## Installation

```bash
# From source
go install github.com/grcengineering/ocean/cmd/ocean@latest

# Or download binary
curl -sSL https://ocean.grc.engineering/install.sh | sh

# Verify
ocean version
```

## 1. Configure Credentials

OCEAN never stores credentials. Use environment variables or external secret providers.

```bash
export OKTA_API_TOKEN="your-token-here"
export OKTA_DOMAIN="your-org.okta.com"
```

## 2. Collect Evidence (Passive)

Passive collection queries system APIs to observe configuration state without modifying anything.

```bash
# List available modules
ocean modules list

# Collect MFA policy evidence from Okta
ocean collect okta.mfa_policy

# Output: JSON evidence normalized to OCEAN Evidence Schema
```

Evidence is normalized to the OCEAN Evidence Schema with full provenance metadata. The `confidence_level` is set to `passive_observation`.

## 3. Run Active Test

Active testing attempts what controls should prevent and records whether the control blocked it. Every tester declares a safety classification.

```bash
# List testers and their safety classifications
ocean modules list --type tester

# Run a safe active test
ocean test okta.mfa_bypass --target production
# Pre-flight: ✓ Safety: safe | ✓ Scope: production | ✓ Authorization: auto-approved
# Result: MFA bypass blocked (control effective)
# Transcript saved with active_verification confidence
```

Safety classifications control authorization requirements:

| Classification | Authorization | Description |
|---------------|--------------|-------------|
| `safe` | Auto-approved | Read-only probes, no side effects |
| `observable` | Prompt | Creates audit trail entries |
| `reversible` | Explicit | Makes changes, auto-reverts after |
| `destructive` | Explicit + warning | Permanent changes, manual cleanup |

## 4. Evaluate Control

Evaluate control effectiveness using YAML presets or custom CEL expressions.

```bash
# Using a YAML preset
ocean evaluate control.mfa_enforcement

# Using custom CEL expression
ocean evaluate control.mfa_enforcement \
  --cel 'evidence.mfa_policy.enforcement == "required" && evidence.test_result.blocked == true'
```

## 5. Dual-Mode Verification

Run both collector + tester and evaluate in a single command for highest confidence.

```bash
# Run both collector + tester and evaluate
ocean verify control.mfa_enforcement
# Output: Unified status with high confidence (both passive + active evidence)
```

When passive observation and active verification agree, confidence is `high`. If they disagree, the active test result takes precedence for behavioral assertions and the discrepancy is highlighted.

## 6. Query History

Query historical evidence and calculate uptime metrics for the "StatusPage for Compliance" view.

```bash
ocean history --control mfa_enforcement --days 180
# Output: Time-series with uptime percentage (e.g., 99.94%)
```

Gaps in collection are clearly indicated, never interpolated or hidden.

## 7. Schedule Continuous Monitoring

Automate evidence collection and safe testing on a recurring schedule.

```bash
ocean schedule add --cron "0 2 * * *" --control mfa_enforcement
# Runs daily at 2 AM UTC: collects evidence, runs safe tests, evaluates
```

Scheduled active tests respect safety classifications and environment scoping. Tests marked `reversible` or higher require pre-authorized approval configured at schedule creation time.

## 8. Generate Report

Produce human-readable compliance reports.

```bash
ocean report --format markdown --period 2026-01-01:2026-06-30
```

Reports distinguish passive observations from active test results and display failures prominently per the Radical Transparency principle.

## 9. (Optional) Sign Evidence with Corsair

For audit-grade independent verification, pipe OCEAN evidence to [Corsair](https://grcorsair.com) to produce CPOEs (Certificates of Proof of Operational Effectiveness).

```bash
# Pipe evidence to Corsair for cryptographic signing
ocean collect okta.mfa_policy | corsair sign --output cpoe.jwt

# Or export all control statuses and sign in batch
ocean verify control.mfa_enforcement --output json | corsair sign --mapping-pack ocean
```

Corsair signs OCEAN evidence into W3C JWT-VC format (Verifiable Credentials) using Ed25519, enabling any third party to independently verify your compliance claims without trusting the OCEAN operator. See [grcorsair.com](https://grcorsair.com) for setup.

---

## Control Definition Example

Controls are defined as YAML files that map evidence sources to effectiveness assertions.

**`controls/iam/mfa_enforcement.yaml`**:

```yaml
id: mfa_enforcement
name: "MFA Enforcement for All Users"
description: "Verify MFA is enforced for all user accounts"
threat_mitigated: "Credential compromise via password-only authentication"

collectors:
  - okta.mfa_policy

testers:
  - okta.mfa_bypass

evaluation:
  # CEL expression
  cel: |
    evidence.mfa_policy.enforcement == "required"
    && evidence.mfa_policy.user_exceptions.size() == 0
    && evidence.test_result.blocked == true

  # OR use a preset instead:
  # preset: all_users_mfa_enforced

framework_mappings:
  - framework: soc2
    control: CC6.1
  - framework: iso27001
    control: A.9.4.2
  - framework: nist_csf
    control: PR.AC-7
```

---

## What's Next

- **Add more modules**: `ocean modules list` shows all available collectors and testers
- **Define custom controls**: Create YAML control definitions in `controls/`
- **Write CEL expressions**: Define organization-specific compliance conditions
- **Build custom modules**: Follow the Collector or Tester interface to extend OCEAN
- **Enable scheduling**: Set up continuous monitoring for all controls
- **Integrate with GRC platforms**: Use server mode (`ocean serve`) to expose the REST API
- **Add cryptographic provenance**: Install [Corsair](https://grcorsair.com) and pipe OCEAN output for audit-grade CPOEs
