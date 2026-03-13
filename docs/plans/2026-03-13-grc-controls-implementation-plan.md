# GRC Controls Shared Crate Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a Cargo workspace with 4 shared crates (`grc-controls-models`, `grc-controls-apis`, `grc-controls-observers`, `grc-controls-testers`) that both OCEAN and HTH consume, eliminating duplicated API clients, domain types, and scanning logic.

**Architecture:** Mono-workspace with layered dependencies: models → apis → observers/testers → binaries. Evidence normalization is first-class in models. Credential management lives with API clients. Platform-specific code gated by Cargo features. See `docs/plans/2026-03-13-grc-controls-shared-crate-design.md`.

**Tech Stack:** Rust 2024 edition, Cargo workspaces, serde/serde_json, chrono, uuid, ureq (sync HTTP for OCEAN observers), reqwest (async HTTP for HTH providers), anyhow/thiserror, secrecy (credential handling).

**Execution Strategy:** Use Agent Orchestrator (`ao`) for parallel task execution. Tasks are grouped into phases; within each phase, independent tasks run as parallel ao agents in isolated worktrees. Create GitHub issues for each parallelizable task, then `ao batch-spawn`.

---

## Phase 0: Workspace Scaffold (Sequential — Foundation)

### Task 0.1: Create workspace repo and scaffold all crates

This task MUST complete before any other work begins. It creates the empty workspace structure that all subsequent tasks build on.

**Files:**
- Create: `grc-controls/Cargo.toml` (workspace root)
- Create: `grc-controls/grc-controls-models/Cargo.toml`
- Create: `grc-controls/grc-controls-models/src/lib.rs`
- Create: `grc-controls/grc-controls-apis/Cargo.toml`
- Create: `grc-controls/grc-controls-apis/src/lib.rs`
- Create: `grc-controls/grc-controls-observers/Cargo.toml`
- Create: `grc-controls/grc-controls-observers/src/lib.rs`
- Create: `grc-controls/grc-controls-testers/Cargo.toml`
- Create: `grc-controls/grc-controls-testers/src/lib.rs`

**Step 1: Create workspace directory**

```bash
mkdir -p ~/Code/grc-controls
cd ~/Code/grc-controls
git init
```

**Step 2: Create workspace Cargo.toml**

```toml
# grc-controls/Cargo.toml
[workspace]
resolver = "2"
members = [
    "grc-controls-models",
    "grc-controls-apis",
    "grc-controls-observers",
    "grc-controls-testers",
]

[workspace.package]
edition = "2024"
license = "MIT"
repository = "https://github.com/grcengineering/grc-controls"

[workspace.dependencies]
# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"

# IDs and time
uuid = { version = "1", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }

# Error handling
anyhow = "1"
thiserror = "1"

# HTTP (sync — OCEAN observers)
ureq = { version = "2", features = ["json"] }

# HTTP (async — HTH providers)
reqwest = { version = "0.12", features = ["json"] }
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"

# Security
secrecy = { version = "0.10", features = ["serde"] }

# Logging
tracing = "0.1"
```

**Step 3: Scaffold grc-controls-models**

```toml
# grc-controls-models/Cargo.toml
[package]
name = "grc-controls-models"
version = "0.1.0"
edition.workspace = true
description = "Shared domain types and evidence normalization for GRC control assessment"

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
uuid = { workspace = true }
chrono = { workspace = true }
thiserror = { workspace = true }
```

```rust
// grc-controls-models/src/lib.rs
pub mod control;
pub mod evidence;
pub mod compliance;
pub mod severity;
pub mod normalize;
```

**Step 4: Scaffold grc-controls-apis**

```toml
# grc-controls-apis/Cargo.toml
[package]
name = "grc-controls-apis"
version = "0.1.0"
edition.workspace = true
description = "Platform API clients and credential management for GRC control assessment"

[dependencies]
grc-controls-models = { path = "../grc-controls-models" }
serde = { workspace = true }
serde_json = { workspace = true }
anyhow = { workspace = true }
thiserror = { workspace = true }
secrecy = { workspace = true }
tracing = { workspace = true }

# Sync HTTP (used by OCEAN-style observers)
ureq = { workspace = true, optional = true }

# Async HTTP (used by HTH-style providers)
reqwest = { workspace = true, optional = true }
tokio = { workspace = true, optional = true }
async-trait = { workspace = true, optional = true }

[features]
default = ["sync", "github", "okta"]
sync = ["ureq"]
async = ["reqwest", "tokio", "async-trait"]
github = []
okta = []
```

```rust
// grc-controls-apis/src/lib.rs
pub mod credentials;

#[cfg(feature = "github")]
pub mod github;

#[cfg(feature = "okta")]
pub mod okta;
```

**Step 5: Scaffold grc-controls-observers**

```toml
# grc-controls-observers/Cargo.toml
[package]
name = "grc-controls-observers"
version = "0.1.0"
edition.workspace = true
description = "Passive security control scanning for GRC assessment"

[dependencies]
grc-controls-models = { path = "../grc-controls-models" }
grc-controls-apis = { path = "../grc-controls-apis" }
serde = { workspace = true }
serde_json = { workspace = true }
anyhow = { workspace = true }
uuid = { workspace = true }
chrono = { workspace = true }
tracing = { workspace = true }

[features]
default = ["github", "okta"]
github = ["grc-controls-apis/github"]
okta = ["grc-controls-apis/okta"]
```

```rust
// grc-controls-observers/src/lib.rs
pub mod observer;

#[cfg(feature = "github")]
pub mod github;

#[cfg(feature = "okta")]
pub mod okta;
```

**Step 6: Scaffold grc-controls-testers**

```toml
# grc-controls-testers/Cargo.toml
[package]
name = "grc-controls-testers"
version = "0.1.0"
edition.workspace = true
description = "Active security control testing for GRC assessment"

[dependencies]
grc-controls-models = { path = "../grc-controls-models" }
grc-controls-apis = { path = "../grc-controls-apis" }
serde = { workspace = true }
serde_json = { workspace = true }
anyhow = { workspace = true }
uuid = { workspace = true }
chrono = { workspace = true }
tracing = { workspace = true }

[features]
default = ["github", "okta"]
github = ["grc-controls-apis/github"]
okta = ["grc-controls-apis/okta"]
```

```rust
// grc-controls-testers/src/lib.rs
pub mod tester;
pub mod safety;
pub mod transcript;

#[cfg(feature = "github")]
pub mod github;

#[cfg(feature = "okta")]
pub mod okta;
```

**Step 7: Verify workspace compiles**

```bash
cd ~/Code/grc-controls
export PATH="$HOME/.cargo/bin:$PATH"
cargo build
```

Expected: Compiles with no errors (empty crates).

**Step 8: Commit**

```bash
git add -A
git commit -m "scaffold: create grc-controls workspace with 4 shared crates"
```

---

## Phase 1: grc-controls-models (Sequential — Must Complete Before Phase 2)

### Task 1.1: Control result types (from HTH)

Migrate `ControlResult`, `CheckResult`, `ControlStatus`, `CheckStatus` from HTH's `hth-core/src/models/report.rs`.

**Files:**
- Create: `grc-controls-models/src/control.rs`
- Test: `grc-controls-models/src/control.rs` (inline `#[cfg(test)]`)

**Step 1: Write the failing test**

```rust
// grc-controls-models/src/control.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_status_serializes_lowercase() {
        let status = ControlStatus::Pass;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"pass\"");
    }

    #[test]
    fn check_result_with_error() {
        let check = CheckResult {
            check_id: "gh-1.1.1".to_string(),
            description: "Branch protection enabled".to_string(),
            status: CheckStatus::Error,
            actual: None,
            expected: true,
            error: Some("API timeout".to_string()),
            duration_ms: 5000,
        };
        assert_eq!(check.status, CheckStatus::Error);
        assert!(check.error.is_some());
    }

    #[test]
    fn control_result_summary() {
        let result = ControlResult {
            control_id: "gh-1.1".to_string(),
            title: "Branch Protection".to_string(),
            severity: Severity::High,
            profile_level: 1,
            status: ControlStatus::Pass,
            checks: vec![],
            compliance: ComplianceMapping::default(),
        };
        assert_eq!(result.status, ControlStatus::Pass);
    }
}
```

**Step 2: Implement types**

```rust
// grc-controls-models/src/control.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ControlStatus {
    Pass,
    Fail,
    Skip,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Fail,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResult {
    pub control_id: String,
    pub title: String,
    pub severity: Severity,
    pub profile_level: u8,
    pub status: ControlStatus,
    pub checks: Vec<CheckResult>,
    pub compliance: ComplianceMapping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub check_id: String,
    pub description: String,
    pub status: CheckStatus,
    pub actual: Option<serde_json::Value>,
    pub expected: bool,
    pub error: Option<String>,
    pub duration_ms: u64,
}

// Re-export from sibling modules
pub use crate::severity::Severity;
pub use crate::compliance::ComplianceMapping;
```

**Step 3: Run tests**

```bash
cargo test -p grc-controls-models
```

**Step 4: Commit**

```bash
git add grc-controls-models/src/control.rs
git commit -m "feat(models): add ControlResult, CheckResult, ControlStatus types"
```

### Task 1.2: Severity types

**Files:**
- Create: `grc-controls-models/src/severity.rs`

**Step 1: Write tests + implementation**

```rust
// grc-controls-models/src/severity.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_id(&self) -> i32 {
        match self {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical < Severity::Low);
    }

    #[test]
    fn severity_serializes_lowercase() {
        let json = serde_json::to_string(&Severity::High).unwrap();
        assert_eq!(json, "\"high\"");
    }

    #[test]
    fn severity_to_id() {
        assert_eq!(Severity::Critical.as_id(), 4);
        assert_eq!(Severity::Low.as_id(), 1);
    }
}
```

**Step 2: Run tests, commit**

```bash
cargo test -p grc-controls-models
git add grc-controls-models/src/severity.rs
git commit -m "feat(models): add Severity enum with ordering and ID mapping"
```

### Task 1.3: Compliance framework mappings

Unify OCEAN's `FrameworkMapping` and HTH's `ComplianceMapping` + `Framework` enum.

**Files:**
- Create: `grc-controls-models/src/compliance.rs`

**Step 1: Write tests + implementation**

```rust
// grc-controls-models/src/compliance.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Framework {
    #[serde(rename = "soc2")]
    Soc2,
    #[serde(rename = "nist-800-53")]
    Nist80053,
    #[serde(rename = "iso-27001")]
    Iso27001,
    #[serde(rename = "pci-dss")]
    PciDss,
    #[serde(rename = "disa-stig")]
    DisaStig,
    #[serde(rename = "cis")]
    Cis,
}

impl Framework {
    pub fn display_name(&self) -> &'static str {
        match self {
            Framework::Soc2 => "SOC 2",
            Framework::Nist80053 => "NIST 800-53",
            Framework::Iso27001 => "ISO 27001",
            Framework::PciDss => "PCI DSS",
            Framework::DisaStig => "DISA STIG",
            Framework::Cis => "CIS Controls",
        }
    }

    pub fn slug(&self) -> &'static str {
        match self {
            Framework::Soc2 => "soc2",
            Framework::Nist80053 => "nist-800-53",
            Framework::Iso27001 => "iso-27001",
            Framework::PciDss => "pci-dss",
            Framework::DisaStig => "disa-stig",
            Framework::Cis => "cis",
        }
    }
}

/// Unified compliance mapping — covers both OCEAN's per-framework
/// list and HTH's flat Vec<String> per framework.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComplianceMapping {
    #[serde(default)]
    pub soc2: Vec<String>,
    #[serde(default)]
    pub nist_800_53: Vec<String>,
    #[serde(default)]
    pub iso_27001: Vec<String>,
    #[serde(default)]
    pub pci_dss: Vec<String>,
    #[serde(default)]
    pub disa_stig: Vec<String>,
    #[serde(default)]
    pub cis: Vec<String>,
}

impl ComplianceMapping {
    pub fn controls_for(&self, framework: Framework) -> &[String] {
        match framework {
            Framework::Soc2 => &self.soc2,
            Framework::Nist80053 => &self.nist_800_53,
            Framework::Iso27001 => &self.iso_27001,
            Framework::PciDss => &self.pci_dss,
            Framework::DisaStig => &self.disa_stig,
            Framework::Cis => &self.cis,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framework_roundtrip() {
        let f = Framework::Soc2;
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, "\"soc2\"");
        let back: Framework = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Framework::Soc2);
    }

    #[test]
    fn compliance_mapping_default_empty() {
        let m = ComplianceMapping::default();
        assert!(m.soc2.is_empty());
        assert!(m.controls_for(Framework::Soc2).is_empty());
    }
}
```

**Step 2: Run tests, commit**

```bash
cargo test -p grc-controls-models
git add grc-controls-models/src/compliance.rs
git commit -m "feat(models): add Framework enum and ComplianceMapping"
```

### Task 1.4: Evidence types (from OCEAN)

Migrate OCEAN's core evidence types: `Evidence`, `StatusId`, `ConfidenceLevel`, `Finding`, `Observable`, `Metadata`, `ModuleInfo`, `SourceInfo`, `Enrichment`.

**Files:**
- Create: `grc-controls-models/src/evidence.rs`

**Source reference:** `/Users/p4gs/Code/OCEAN/src/evidence/mod.rs`

**Step 1: Write tests + implementation**

Copy the following types from OCEAN's `evidence/mod.rs`, keeping exact field names and serde attributes:

- `StatusId` enum (i32-backed): Unknown(0), Effective(1), Ineffective(2), Other(99)
- `ConfidenceLevel` enum: PassiveObservation, ActiveVerification
- `ModuleInfo` struct: name, version, module_type (renamed "type" in JSON)
- `SourceInfo` struct: system, api_version, endpoint
- `Metadata` struct: module, source, original_time, processed_time, safety_classification
- `Observable` struct: obs_type (renamed "type"), value, name
- `Finding` struct: title, description, severity_id
- `Enrichment` struct: enrichment_type (renamed "type"), data, enriched_time
- `Evidence` struct: all fields including id, control_id, class_uid, category_uid, activity_id, time, confidence_level, metadata, observables, status_id, status, raw_data, findings, test_transcript, enrichments

Tests:
```rust
#[test]
fn status_id_effective_value() {
    assert_eq!(StatusId::Effective as i32, 1);
}

#[test]
fn evidence_serializes_with_all_fields() {
    let ev = Evidence { /* ... populate all fields ... */ };
    let json = serde_json::to_value(&ev).unwrap();
    assert!(json.get("control_id").is_some());
    assert!(json.get("status_id").is_some());
}
```

**Step 2: Run tests, commit**

```bash
cargo test -p grc-controls-models
git add grc-controls-models/src/evidence.rs
git commit -m "feat(models): add Evidence types (OCSF-aligned)"
```

### Task 1.5: TestTranscript types (from OCEAN)

Migrate transcript types from OCEAN's `evidence/transcript.rs`.

**Files:**
- Create: `grc-controls-models/src/transcript.rs`

**Source reference:** `/Users/p4gs/Code/OCEAN/src/evidence/transcript.rs`

Types to migrate:
- `TestTranscript`: actions_attempted, observations, cleanup_actions
- `TranscriptAction`: action, timestamp, parameters
- `TranscriptObservation`: observation, timestamp, expected
- `TranscriptCleanup`: action, timestamp, success
- `TranscriptRecorder`: builder pattern with record_action, record_observation, record_cleanup, finalize

**Step 1: Copy types, write tests, run, commit**

```bash
cargo test -p grc-controls-models
git commit -m "feat(models): add TestTranscript and TranscriptRecorder"
```

### Task 1.6: Evidence normalization — `ControlResult → Evidence`

This is the critical normalization function. It maps HTH-style `ControlResult` to OCEAN-style `Evidence`.

**Files:**
- Create: `grc-controls-models/src/normalize.rs`

**Step 1: Write failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{ControlResult, ControlStatus, CheckResult, CheckStatus};
    use crate::severity::Severity;
    use crate::compliance::ComplianceMapping;

    #[test]
    fn passing_control_becomes_effective_evidence() {
        let cr = ControlResult {
            control_id: "gh-1.1".to_string(),
            title: "Branch Protection".to_string(),
            severity: Severity::High,
            profile_level: 1,
            status: ControlStatus::Pass,
            checks: vec![CheckResult {
                check_id: "gh-1.1.1".to_string(),
                description: "Default branch protected".to_string(),
                status: CheckStatus::Pass,
                actual: Some(serde_json::json!(true)),
                expected: true,
                error: None,
                duration_ms: 150,
            }],
            compliance: ComplianceMapping::default(),
        };

        let evidence = normalize_control_result(&cr, "github");
        assert_eq!(evidence.status_id, StatusId::Effective);
        assert_eq!(evidence.control_id, "gh-1.1");
        assert_eq!(evidence.confidence_level, ConfidenceLevel::PassiveObservation);
        assert!(!evidence.findings.is_empty());
    }

    #[test]
    fn failing_control_becomes_ineffective_evidence() {
        let cr = ControlResult {
            control_id: "gh-1.1".to_string(),
            title: "Branch Protection".to_string(),
            severity: Severity::High,
            profile_level: 1,
            status: ControlStatus::Fail,
            checks: vec![],
            compliance: ComplianceMapping::default(),
        };

        let evidence = normalize_control_result(&cr, "github");
        assert_eq!(evidence.status_id, StatusId::Ineffective);
    }

    #[test]
    fn skipped_control_becomes_unknown_evidence() {
        let cr = ControlResult {
            control_id: "gh-1.1".to_string(),
            title: "Branch Protection".to_string(),
            severity: Severity::Medium,
            profile_level: 2,
            status: ControlStatus::Skip,
            checks: vec![],
            compliance: ComplianceMapping::default(),
        };

        let evidence = normalize_control_result(&cr, "github");
        assert_eq!(evidence.status_id, StatusId::Unknown);
    }

    #[test]
    fn error_control_becomes_unknown_evidence() {
        let cr = ControlResult {
            control_id: "gh-1.1".to_string(),
            title: "Branch Protection".to_string(),
            severity: Severity::High,
            profile_level: 1,
            status: ControlStatus::Error,
            checks: vec![],
            compliance: ComplianceMapping::default(),
        };

        let evidence = normalize_control_result(&cr, "github");
        assert_eq!(evidence.status_id, StatusId::Unknown);
    }
}
```

**Step 2: Implement normalization**

```rust
// grc-controls-models/src/normalize.rs
use crate::control::{ControlResult, ControlStatus};
use crate::evidence::*;

/// Maps a ControlResult (HTH-style) to an Evidence record (OCSF-style).
///
/// Status mapping:
///   Pass  → Effective
///   Fail  → Ineffective
///   Skip  → Unknown
///   Error → Unknown
pub fn normalize_control_result(cr: &ControlResult, source_system: &str) -> Evidence {
    let now = chrono::Utc::now();

    let status_id = match cr.status {
        ControlStatus::Pass => StatusId::Effective,
        ControlStatus::Fail => StatusId::Ineffective,
        ControlStatus::Skip | ControlStatus::Error => StatusId::Unknown,
    };

    let findings: Vec<Finding> = cr.checks.iter().map(|check| {
        Finding {
            title: check.description.clone(),
            description: match &check.error {
                Some(e) => format!("{}: {}", check.description, e),
                None => check.description.clone(),
            },
            severity_id: cr.severity.as_id(),
        }
    }).collect();

    // If no checks produced findings, create a summary finding
    let findings = if findings.is_empty() {
        vec![Finding {
            title: cr.title.clone(),
            description: format!("{}: {:?}", cr.title, cr.status),
            severity_id: cr.severity.as_id(),
        }]
    } else {
        findings
    };

    Evidence {
        id: uuid::Uuid::new_v4(),
        control_id: cr.control_id.clone(),
        class_uid: 1003,
        category_uid: 2,
        activity_id: 1,
        time: now,
        confidence_level: ConfidenceLevel::PassiveObservation,
        metadata: Metadata {
            module: ModuleInfo {
                name: format!("hth.{}", cr.control_id),
                version: "0.1.0".to_string(),
                module_type: "observer".to_string(),
            },
            source: SourceInfo {
                system: source_system.to_string(),
                api_version: "v1".to_string(),
                endpoint: String::new(),
            },
            original_time: None,
            processed_time: now,
            safety_classification: None,
        },
        observables: vec![Observable {
            obs_type: "resource".to_string(),
            value: cr.control_id.clone(),
            name: String::new(),
        }],
        status_id,
        status: format!("{}: {:?}", cr.title, cr.status),
        raw_data: serde_json::to_value(cr).unwrap_or_default(),
        findings,
        test_transcript: None,
        enrichments: vec![],
    }
}
```

**Step 3: Run tests, commit**

```bash
cargo test -p grc-controls-models
git commit -m "feat(models): add ControlResult → Evidence normalization"
```

### Task 1.7: Wire up lib.rs exports and verify

**Files:**
- Modify: `grc-controls-models/src/lib.rs`

```rust
pub mod compliance;
pub mod control;
pub mod evidence;
pub mod normalize;
pub mod severity;
pub mod transcript;

// Re-exports for convenience
pub use compliance::{ComplianceMapping, Framework};
pub use control::{CheckResult, CheckStatus, ControlResult, ControlStatus};
pub use evidence::{
    ConfidenceLevel, Enrichment, Evidence, Finding, Metadata, ModuleInfo, Observable, SourceInfo,
    StatusId,
};
pub use normalize::normalize_control_result;
pub use severity::Severity;
pub use transcript::{TestTranscript, TranscriptRecorder};
```

```bash
cargo test -p grc-controls-models
cargo clippy -p grc-controls-models -- -D warnings
git commit -m "feat(models): wire up lib.rs re-exports, clippy clean"
```

---

## Phase 2: grc-controls-apis (Sequential — Must Complete Before Phase 3)

### Task 2.1: Credential management

**Files:**
- Create: `grc-controls-apis/src/credentials.rs`

**Step 1: Write types**

```rust
// grc-controls-apis/src/credentials.rs
use secrecy::SecretString;
use std::collections::HashMap;

/// Platform-specific credentials resolved from environment or config.
#[derive(Debug, Clone)]
pub struct GitHubCredentials {
    pub token: SecretString,
    pub org: Option<String>,
    pub owner: Option<String>,
    pub repo: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OktaCredentials {
    pub domain: String,
    pub token: SecretString,
}

impl GitHubCredentials {
    /// Resolve from environment variables.
    /// Reads: GITHUB_TOKEN or GH_TOKEN, GITHUB_ORG or GH_ORG,
    ///        GITHUB_OWNER, GITHUB_REPO or GH_REPO
    pub fn from_env() -> Result<Self, CredentialError> {
        let token = std::env::var("GITHUB_TOKEN")
            .or_else(|_| std::env::var("GH_TOKEN"))
            .map_err(|_| CredentialError::Missing {
                name: "GITHUB_TOKEN".to_string(),
            })?;

        Ok(Self {
            token: SecretString::from(token),
            org: std::env::var("GITHUB_ORG")
                .or_else(|_| std::env::var("GH_ORG"))
                .ok(),
            owner: std::env::var("GITHUB_OWNER").ok(),
            repo: std::env::var("GITHUB_REPO")
                .or_else(|_| std::env::var("GH_REPO"))
                .ok(),
        })
    }

    /// Resolve from a HashMap config (OCEAN's current pattern).
    pub fn from_config(config: &HashMap<String, String>) -> Result<Self, CredentialError> {
        let token = config
            .get("GITHUB_TOKEN")
            .ok_or_else(|| CredentialError::Missing {
                name: "GITHUB_TOKEN".to_string(),
            })?;

        Ok(Self {
            token: SecretString::from(token.clone()),
            org: config.get("GITHUB_ORG").cloned(),
            owner: config.get("GITHUB_OWNER").cloned(),
            repo: config.get("GITHUB_REPO").cloned(),
        })
    }
}

impl OktaCredentials {
    pub fn from_env() -> Result<Self, CredentialError> {
        let domain = std::env::var("OKTA_DOMAIN")
            .map_err(|_| CredentialError::Missing {
                name: "OKTA_DOMAIN".to_string(),
            })?;
        let token = std::env::var("OKTA_API_TOKEN")
            .map_err(|_| CredentialError::Missing {
                name: "OKTA_API_TOKEN".to_string(),
            })?;

        Ok(Self {
            domain,
            token: SecretString::from(token),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("Missing required credential: {name}")]
    Missing { name: String },
}
```

**Step 2: Write tests, run, commit**

```bash
cargo test -p grc-controls-apis
git commit -m "feat(apis): add credential management for GitHub and Okta"
```

### Task 2.2: GitHub API client (sync)

Unify OCEAN's `github_common::github_get` and HTH's `GitHubApiClient` into a single typed client.

**Files:**
- Create: `grc-controls-apis/src/github.rs`

**Source references:**
- `/Users/p4gs/Code/OCEAN/src/modules/github_common.rs` — `github_get()`, `DEFAULT_GITHUB_API`, `GITHUB_API_VERSION`
- `/Users/p4gs/Code/how-to-harden/cli/crates/hth-github/src/api.rs` — `GitHubApiClient` (rate limiting, pagination, 404 handling)

**Step 1: Implement sync client**

The sync client uses `ureq` (OCEAN's pattern). It should support:
- Authenticated GET with typed responses
- 404 handling (returns synthetic response, not error)
- Configurable base URL (for testing with mock servers)
- Helper: `mock_server()` and `test_config()` for tests

```rust
// grc-controls-apis/src/github.rs
use anyhow::{anyhow, Result};
use secrecy::ExposeSecret;
use serde_json::Value;

use crate::credentials::GitHubCredentials;

pub const DEFAULT_GITHUB_API: &str = "https://api.github.com";
pub const GITHUB_API_VERSION: &str = "2022-11-28";

pub struct GitHubClient {
    token: secrecy::SecretString,
    base_url: String,
}

impl GitHubClient {
    pub fn new(creds: &GitHubCredentials) -> Self {
        Self {
            token: creds.token.clone(),
            base_url: DEFAULT_GITHUB_API.to_string(),
        }
    }

    pub fn with_base_url(creds: &GitHubCredentials, base_url: &str) -> Self {
        Self {
            token: creds.token.clone(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Authenticated GET. Returns (response_body, http_status_code).
    /// Does NOT error on 404 — returns the body and status for caller to handle.
    pub fn get(&self, path: &str) -> Result<(Value, u16)> {
        let url = format!("{}{}", self.base_url, path);
        let resp = ureq::get(&url)
            .set("Authorization", &format!("Bearer {}", self.token.expose_secret()))
            .set("Accept", "application/vnd.github+json")
            .set("X-GitHub-Api-Version", GITHUB_API_VERSION)
            .set("User-Agent", "grc-controls")
            .call();

        match resp {
            Ok(r) => {
                let status = r.status();
                let body: Value = r.into_json()?;
                Ok((body, status))
            }
            Err(ureq::Error::Status(code, response)) => {
                let body: Value = response.into_json().unwrap_or(Value::Null);
                Ok((body, code))
            }
            Err(e) => Err(anyhow!("GitHub API request failed: {}", e)),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn endpoint_url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

// ─── Test Utilities ──────────────────────────────────────────────────────────

#[cfg(test)]
pub mod test_util {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    pub fn mock_server(status: u16, body: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.to_string();

        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });

        format!("http://{}", addr)
    }

    pub fn test_credentials() -> GitHubCredentials {
        GitHubCredentials {
            token: secrecy::SecretString::from("test-token".to_string()),
            org: Some("test-org".to_string()),
            owner: Some("test-owner".to_string()),
            repo: Some("test-repo".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test_util::*;

    #[test]
    fn get_200_returns_body_and_status() {
        let url = mock_server(200, r#"{"key":"value"}"#);
        let creds = test_credentials();
        let client = GitHubClient::with_base_url(&creds, &url);
        let (body, status) = client.get("/test").unwrap();
        assert_eq!(status, 200);
        assert_eq!(body["key"], "value");
    }

    #[test]
    fn get_404_returns_body_not_error() {
        let url = mock_server(404, r#"{"message":"Not Found"}"#);
        let creds = test_credentials();
        let client = GitHubClient::with_base_url(&creds, &url);
        let (body, status) = client.get("/missing").unwrap();
        assert_eq!(status, 404);
        assert_eq!(body["message"], "Not Found");
    }
}
```

**Step 2: Run tests, commit**

```bash
cargo test -p grc-controls-apis
git commit -m "feat(apis): add sync GitHub API client with test utilities"
```

### Task 2.3: Okta API client (sync)

**Files:**
- Create: `grc-controls-apis/src/okta.rs`

Similar pattern to GitHub client but for Okta:
- Base URL: `https://{domain}`
- Auth: `SSWS {token}` header
- Same mock_server test pattern

```bash
cargo test -p grc-controls-apis
git commit -m "feat(apis): add sync Okta API client"
```

### Task 2.4: Wire up lib.rs and verify

```rust
// grc-controls-apis/src/lib.rs
pub mod credentials;

#[cfg(feature = "github")]
pub mod github;

#[cfg(feature = "okta")]
pub mod okta;

pub use credentials::{CredentialError, GitHubCredentials, OktaCredentials};
```

```bash
cargo test -p grc-controls-apis
cargo clippy -p grc-controls-apis -- -D warnings
git commit -m "feat(apis): wire up lib.rs exports, clippy clean"
```

---

## Phase 3: Observers + Testers (Parallel via `ao` — Both Depend on Phase 2)

> **Agent Orchestrator:** Create GitHub issues for Tasks 3.1 and 3.2, then:
> ```bash
> ao batch-spawn grc-controls issue-3.1 issue-3.2
> ```
> These tasks are fully independent and can run in parallel worktrees.

### Task 3.1: grc-controls-observers (ao agent 1)

**Files:**
- Create: `grc-controls-observers/src/observer.rs` — Observer trait
- Create: `grc-controls-observers/src/github/mod.rs`
- Create: `grc-controls-observers/src/github/branch_protection.rs`
- Create: `grc-controls-observers/src/github/repo_security.rs`
- Create: `grc-controls-observers/src/github/dependabot.rs`
- Create: `grc-controls-observers/src/github/code_scanning.rs`
- Create: `grc-controls-observers/src/github/secret_scanning.rs`
- Create: `grc-controls-observers/src/github/actions_permissions.rs`
- Create: `grc-controls-observers/src/github/workflow_permissions.rs`

**Source references:**
- Observer trait: `/Users/p4gs/Code/OCEAN/src/module/observer.rs`
- Module trait: `/Users/p4gs/Code/OCEAN/src/module/mod.rs`
- GitHub observers: `/Users/p4gs/Code/OCEAN/src/modules/observers/github*.rs`
- GitHub common: `/Users/p4gs/Code/OCEAN/src/modules/github_common.rs`

**Step 1: Define Observer trait**

```rust
// grc-controls-observers/src/observer.rs
use anyhow::Result;
use grc_controls_models::{ControlResult, Evidence};
use std::collections::HashMap;

/// Passive observer that reads API/system state and produces control results.
pub trait Observer: Send + Sync {
    /// Unique identifier (e.g., "github.branch_protection")
    fn id(&self) -> &str;

    /// Human-readable name
    fn name(&self) -> &str;

    /// Source system (e.g., "github", "okta")
    fn source_system(&self) -> &str;

    /// Execute passive observation against live APIs.
    /// Returns raw ControlResult — caller normalizes to Evidence if needed.
    fn observe(&self, config: &HashMap<String, String>) -> Result<Vec<ControlResult>>;

    /// Convenience: observe + normalize to Evidence in one call.
    fn observe_as_evidence(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        let results = self.observe(config)?;
        Ok(results
            .iter()
            .map(|cr| grc_controls_models::normalize_control_result(cr, self.source_system()))
            .collect())
    }
}
```

**Step 2: Migrate GitHub observers**

For each observer in OCEAN (`github.rs`, `github_dependabot.rs`, etc.):
1. Rewrite to use `grc_controls_apis::github::GitHubClient` instead of inline `github_get`
2. Return `ControlResult` instead of `Evidence` (normalization is separate)
3. Keep the same test patterns (mock_server, test_config)

Each observer follows this pattern:

```rust
// Example: grc-controls-observers/src/github/branch_protection.rs
use anyhow::{anyhow, Result};
use grc_controls_apis::github::GitHubClient;
use grc_controls_apis::GitHubCredentials;
use grc_controls_models::*;
use std::collections::HashMap;

use crate::observer::Observer;

pub struct BranchProtectionObserver;

impl Observer for BranchProtectionObserver {
    fn id(&self) -> &str { "github.branch_protection" }
    fn name(&self) -> &str { "GitHub Branch Protection Observer" }
    fn source_system(&self) -> &str { "github" }

    fn observe(&self, config: &HashMap<String, String>) -> Result<Vec<ControlResult>> {
        let creds = GitHubCredentials::from_config(config)?;
        let owner = creds.owner.as_deref()
            .ok_or_else(|| anyhow!("GITHUB_OWNER is required"))?;
        let repo = creds.repo.as_deref()
            .ok_or_else(|| anyhow!("GITHUB_REPO is required"))?;
        let base_url = config.get("GITHUB_API_URL");
        let client = match base_url {
            Some(url) => GitHubClient::with_base_url(&creds, url),
            None => GitHubClient::new(&creds),
        };

        let path = format!("/repos/{}/{}/branches/main/protection", owner, repo);
        let (body, status) = client.get(&path)?;

        let (ctrl_status, checks) = match status {
            200 => (ControlStatus::Pass, vec![CheckResult {
                check_id: "branch_protection.enabled".to_string(),
                description: "Branch protection is enabled on default branch".to_string(),
                status: CheckStatus::Pass,
                actual: Some(body.clone()),
                expected: true,
                error: None,
                duration_ms: 0,
            }]),
            404 => (ControlStatus::Fail, vec![CheckResult {
                check_id: "branch_protection.enabled".to_string(),
                description: "Branch protection is enabled on default branch".to_string(),
                status: CheckStatus::Fail,
                actual: None,
                expected: true,
                error: Some("Branch protection not configured".to_string()),
                duration_ms: 0,
            }]),
            _ => return Err(anyhow!("GitHub API returned status {}", status)),
        };

        Ok(vec![ControlResult {
            control_id: "scm.branch_protection".to_string(),
            title: "Branch Protection".to_string(),
            severity: Severity::High,
            profile_level: 1,
            status: ctrl_status,
            checks,
            compliance: ComplianceMapping::default(),
        }])
    }
}
```

**Repeat for all 7 GitHub observers**, following the same pattern.

**Step 3: Wire up module, run tests, commit**

```rust
// grc-controls-observers/src/github/mod.rs
pub mod branch_protection;
pub mod repo_security;
pub mod dependabot;
pub mod code_scanning;
pub mod secret_scanning;
pub mod actions_permissions;
pub mod workflow_permissions;

pub use branch_protection::BranchProtectionObserver;
pub use repo_security::RepoSecurityObserver;
pub use dependabot::DependabotAlertsObserver;
pub use code_scanning::CodeScanningAlertsObserver;
pub use secret_scanning::SecretScanningAlertsObserver;
pub use actions_permissions::ActionsPermissionsObserver;
pub use workflow_permissions::WorkflowPermissionsObserver;
```

```bash
cargo test -p grc-controls-observers
cargo clippy -p grc-controls-observers -- -D warnings
git commit -m "feat(observers): migrate all GitHub observers to shared crate"
```

### Task 3.2: grc-controls-testers (ao agent 2)

**Files:**
- Create: `grc-controls-testers/src/tester.rs` — Tester trait
- Create: `grc-controls-testers/src/safety.rs` — SafetyClassification, EnvironmentScope
- Create: `grc-controls-testers/src/transcript.rs` — re-export from models
- Create: `grc-controls-testers/src/github/mod.rs`
- Create: `grc-controls-testers/src/github/branch_bypass.rs`
- Create: `grc-controls-testers/src/github/secret_push.rs`

**Source references:**
- Tester trait: `/Users/p4gs/Code/OCEAN/src/module/tester.rs`
- Safety: `/Users/p4gs/Code/OCEAN/src/module/safety.rs`
- Transcript: `/Users/p4gs/Code/OCEAN/src/evidence/transcript.rs`
- GitHub testers: `/Users/p4gs/Code/OCEAN/src/modules/testers/github*.rs`

**Step 1: Define Tester trait + safety types**

```rust
// grc-controls-testers/src/tester.rs
use anyhow::Result;
use grc_controls_models::ControlResult;
use std::collections::HashMap;

use crate::safety::{EnvironmentScope, SafetyClassification};

pub trait Tester: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn source_system(&self) -> &str;
    fn safety_class(&self) -> SafetyClassification;
    fn environment_scope(&self) -> EnvironmentScope;
    fn pre_flight_checks(&self) -> Vec<String>;
    fn cleanup_procedures(&self) -> Vec<String>;
    fn test(&self, config: &HashMap<String, String>) -> Result<Vec<ControlResult>>;
}
```

```rust
// grc-controls-testers/src/safety.rs
// Copy SafetyClassification and EnvironmentScope from OCEAN's safety.rs
```

**Step 2: Migrate GitHub testers**

Migrate `BranchBypassTester` and `SecretPushTester`, rewriting to use `grc_controls_apis::github::GitHubClient` and return `ControlResult` instead of `Evidence`.

Note: `SecretPushTester` uses PUT/DELETE (not just GET), so it needs direct `ureq` calls for write operations. The `GitHubClient` from `grc-controls-apis` handles GET; for PUT/DELETE, the tester can use `ureq` directly with the token from `GitHubCredentials`.

**Step 3: Wire up, test, commit**

```bash
cargo test -p grc-controls-testers
cargo clippy -p grc-controls-testers -- -D warnings
git commit -m "feat(testers): migrate GitHub testers to shared crate"
```

---

## Phase 4: Wire Binaries (Parallel via `ao`)

> **Agent Orchestrator:**
> ```bash
> ao batch-spawn grc-controls issue-4.1 issue-4.2
> ```

### Task 4.1: Wire OCEAN binary (ao agent 1)

**Goal:** Make OCEAN depend on the shared crates and delegate to them for GitHub/Okta observations and tests.

**Files:**
- Modify: `/Users/p4gs/Code/OCEAN/Cargo.toml` — add path deps
- Modify: `/Users/p4gs/Code/OCEAN/src/modules/observers/mod.rs` — register shared observers
- Modify: `/Users/p4gs/Code/OCEAN/src/modules/testers/mod.rs` — register shared testers
- Modify: `/Users/p4gs/Code/OCEAN/src/modules/observers/github*.rs` — replace with thin wrappers

**Approach:** OCEAN keeps its own `Observer` and `Tester` traits (they return `Evidence`, not `ControlResult`). Each OCEAN observer wraps a shared `grc-controls-observers` observer, calling `observe_as_evidence()` to get normalized Evidence directly.

```rust
// Wrapper pattern — OCEAN observer delegates to shared observer
use ocean::module::observer::Observer as OceanObserver;
use grc_controls_observers::observer::Observer as SharedObserver;
use grc_controls_observers::github::BranchProtectionObserver as SharedBranchProtection;

pub struct BranchProtectionObserver;

impl OceanObserver for BranchProtectionObserver {
    fn observe(&self, config: &HashMap<String, String>) -> Result<Vec<Evidence>> {
        SharedBranchProtection.observe_as_evidence(config)
    }
}
```

Alternative (simpler): If OCEAN refactors its `Observer` trait to also return `ControlResult` and normalize separately, the wrapping is unnecessary. This is the cleaner long-term path but requires touching more OCEAN code.

**Decision for implementer:** Start with thin wrappers (less risk), refactor OCEAN's traits in a follow-up.

**Step 1: Add dependencies to OCEAN's Cargo.toml**

```toml
# Add to [dependencies]
grc-controls-models = { path = "../grc-controls/grc-controls-models" }
grc-controls-apis = { path = "../grc-controls/grc-controls-apis" }
grc-controls-observers = { path = "../grc-controls/grc-controls-observers" }
grc-controls-testers = { path = "../grc-controls/grc-controls-testers" }
```

**Step 2: Replace OCEAN's github_common.rs with re-export from grc-controls-apis**

**Step 3: Replace each GitHub observer with wrapper, run tests after each**

**Step 4: Replace each GitHub tester with wrapper, run tests after each**

**Step 5: Full verification**

```bash
cd ~/Code/OCEAN
export PATH="$HOME/.cargo/bin:$PATH"
cargo build
cargo test
cargo clippy -- -D warnings
```

### Task 4.2: Wire HTH binary (ao agent 2)

**Goal:** Make HTH depend on the shared crates, replacing `hth-github` and `hth-okta` with `grc-controls-apis`.

**Files:**
- Modify: `/Users/p4gs/Code/how-to-harden/cli/Cargo.toml` — add workspace members or path deps
- Modify: `/Users/p4gs/Code/how-to-harden/cli/crates/hth/Cargo.toml` — depend on shared crates
- Modify: `/Users/p4gs/Code/how-to-harden/cli/crates/hth-github/src/lib.rs` — delegate to shared client
- Modify: `/Users/p4gs/Code/how-to-harden/cli/crates/hth/src/main.rs` — wire vendor registry

**Approach:** HTH's `VendorProvider` trait is async; `grc-controls-apis` provides sync clients. Two options:

1. **Add async feature to grc-controls-apis** — `GitHubClient` gets an async variant using reqwest. HTH's `GitHubProvider` wraps it.
2. **Keep hth-github as a thin async wrapper** around the shared sync client, using `tokio::task::spawn_blocking` for sync-to-async bridging.

**Recommended: Option 1** — add async support to `grc-controls-apis` behind the `async` feature flag. This is cleaner and avoids blocking the async runtime.

**Step 1: Add async GitHub client to grc-controls-apis**

```rust
// grc-controls-apis/src/github.rs (add behind #[cfg(feature = "async")])
pub struct AsyncGitHubClient {
    token: secrecy::SecretString,
    base_url: String,
    http: reqwest::Client,
}

impl AsyncGitHubClient {
    pub async fn get(&self, path: &str) -> Result<(Value, u16)> { /* ... */ }
    pub async fn put(&self, path: &str, body: &Value) -> Result<(Value, u16)> { /* ... */ }
    pub async fn delete(&self, path: &str) -> Result<(Value, u16)> { /* ... */ }
}
```

**Step 2: Make hth-github delegate to shared async client**

**Step 3: Full verification**

```bash
cd ~/Code/how-to-harden/cli
export PATH="$HOME/.cargo/bin:$PATH"
cargo build
cargo test
cargo clippy -- -D warnings
```

---

## Phase 5: Integration Verification (Sequential)

### Task 5.1: Cross-workspace integration test

**Files:**
- Create: `grc-controls/tests/integration.rs`

**Step 1: Write integration test**

```rust
// Tests that the full pipeline works: observe → normalize → evidence
#[test]
fn github_observer_produces_normalized_evidence() {
    use grc_controls_observers::github::BranchProtectionObserver;
    use grc_controls_observers::observer::Observer;
    use grc_controls_models::StatusId;
    use grc_controls_apis::github::test_util::mock_server;

    let url = mock_server(200, r#"{"url":"https://api.github.com/...","required_status_checks":{}}"#);
    let mut config = std::collections::HashMap::new();
    config.insert("GITHUB_TOKEN".to_string(), "test".to_string());
    config.insert("GITHUB_OWNER".to_string(), "test-org".to_string());
    config.insert("GITHUB_REPO".to_string(), "test-repo".to_string());
    config.insert("GITHUB_API_URL".to_string(), url);

    let evidence = BranchProtectionObserver.observe_as_evidence(&config).unwrap();
    assert_eq!(evidence[0].status_id, StatusId::Effective);
    assert_eq!(evidence[0].metadata.source.system, "github");
}
```

**Step 2: Run all tests across workspace**

```bash
cd ~/Code/grc-controls
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

**Step 3: Run OCEAN tests**

```bash
cd ~/Code/OCEAN
cargo test
```

**Step 4: Run HTH tests**

```bash
cd ~/Code/how-to-harden/cli
cargo test
```

**Step 5: Commit and tag**

```bash
cd ~/Code/grc-controls
git tag v0.1.0
git commit -m "feat: grc-controls v0.1.0 — shared crate workspace complete"
```

---

## Execution Summary

| Phase | Tasks | Parallelizable | Agent Orchestrator |
|-------|-------|---------------|-------------------|
| 0 | Scaffold workspace | No (foundation) | Manual |
| 1 | Models (7 tasks) | No (sequential build-up) | Manual |
| 2 | APIs (4 tasks) | No (sequential build-up) | Manual |
| 3 | Observers + Testers | **Yes (2 agents)** | `ao batch-spawn` |
| 4 | Wire OCEAN + Wire HTH | **Yes (2 agents)** | `ao batch-spawn` |
| 5 | Integration verification | No (must verify all) | Manual |

**Total: ~20 tasks, ~15 commits, 2 parallel phases with `ao`**

---

## Risk Mitigations

1. **OCEAN uses sync HTTP (ureq), HTH uses async (reqwest):** Solved by feature flags in `grc-controls-apis` — `sync` and `async` features provide both client variants.

2. **OCEAN observers return `Evidence`, shared observers return `ControlResult`:** Solved by `observe_as_evidence()` convenience method and thin wrapper pattern in OCEAN.

3. **HTH's `VendorProvider` trait is richer than shared client:** HTH keeps its trait; `GitHubProvider` wraps the shared `AsyncGitHubClient` and adds `resolve_url()`, `terraform_provider_block()`, etc.

4. **Credential resolution differs:** `GitHubCredentials` supports both `from_env()` (HTH pattern) and `from_config(HashMap)` (OCEAN pattern).

5. **Existing tests must not break:** Each migration step runs `cargo test` before committing. No test is deleted — only moved or wrapped.
