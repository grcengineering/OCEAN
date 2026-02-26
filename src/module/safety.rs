use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SafetyClassification
// ---------------------------------------------------------------------------

/// Categorizes a module's potential impact on the target system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SafetyClassification {
    /// Reads publicly available or non-sensitive configuration state.
    Safe,
    /// Reads data in a way that may be logged or visible to the target system.
    Observable,
    /// Makes changes that can be automatically rolled back.
    Reversible,
    /// Makes changes that cannot be automatically reversed.
    Destructive,
}

impl SafetyClassification {
    pub fn requires_explicit_auth(self) -> bool {
        matches!(self, Self::Observable | Self::Reversible | Self::Destructive)
    }

    pub fn requires_warning(self) -> bool {
        matches!(self, Self::Destructive)
    }

    /// Returns the numeric rank for comparison (higher = more restrictive).
    fn rank(self) -> u8 {
        match self {
            Self::Safe => 0,
            Self::Observable => 1,
            Self::Reversible => 2,
            Self::Destructive => 3,
        }
    }
}

impl std::fmt::Display for SafetyClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Safe => "safe",
            Self::Observable => "observable",
            Self::Reversible => "reversible",
            Self::Destructive => "destructive",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// EnvironmentScope
// ---------------------------------------------------------------------------

/// Indicates the environment in which a module operates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvironmentScope {
    Production,
    Staging,
    Isolated,
}

impl std::fmt::Display for EnvironmentScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Production => "production",
            Self::Staging => "staging",
            Self::Isolated => "isolated",
        };
        write!(f, "{s}")
    }
}

/// Returns true if `classification` can run in `target`.
pub fn can_run_in_environment(classification: SafetyClassification, target: EnvironmentScope) -> bool {
    match classification {
        SafetyClassification::Safe => true,
        SafetyClassification::Observable => {
            matches!(target, EnvironmentScope::Production | EnvironmentScope::Staging)
        }
        SafetyClassification::Reversible => {
            matches!(target, EnvironmentScope::Staging | EnvironmentScope::Isolated)
        }
        SafetyClassification::Destructive => {
            matches!(target, EnvironmentScope::Isolated)
        }
    }
}

/// Returns the most restrictive safety classification from a slice.
pub fn highest_safety_classification(classes: &[SafetyClassification]) -> SafetyClassification {
    classes
        .iter()
        .max_by_key(|c| c.rank())
        .copied()
        .unwrap_or(SafetyClassification::Safe)
}

/// Validates that a tester can run in the target environment.
pub fn enforce_scope(tester_id: &str, class: SafetyClassification, target: EnvironmentScope) -> Result<()> {
    if !can_run_in_environment(class, target) {
        return Err(anyhow!(
            "scope violation: tester {tester_id:?} has safety classification {class} \
             which cannot run in {target} environment"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// AuthorizationLevel
// ---------------------------------------------------------------------------

/// How much authorization is required before executing a tester.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationLevel {
    /// No prompt needed (safe tests).
    Auto,
    /// Simple confirmation needed (observable tests).
    Prompt,
    /// Explicit "yes" required (reversible tests).
    Explicit,
    /// Warning plus explicit "yes" required (destructive tests).
    Warning,
}

impl std::fmt::Display for AuthorizationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Auto => "auto",
            Self::Prompt => "prompt",
            Self::Explicit => "explicit",
            Self::Warning => "warning",
        };
        write!(f, "{s}")
    }
}

pub fn required_auth_level(classification: SafetyClassification) -> AuthorizationLevel {
    match classification {
        SafetyClassification::Safe => AuthorizationLevel::Auto,
        SafetyClassification::Observable => AuthorizationLevel::Prompt,
        SafetyClassification::Reversible => AuthorizationLevel::Explicit,
        SafetyClassification::Destructive => AuthorizationLevel::Warning,
    }
}

// ---------------------------------------------------------------------------
// Authorizer trait
// ---------------------------------------------------------------------------

pub trait Authorizer: Send + Sync {
    fn authorize(
        &self,
        test_name: &str,
        classification: SafetyClassification,
        level: AuthorizationLevel,
    ) -> Result<bool>;
}

/// Always authorizes safe tests, rejects everything else.
pub struct AutoAuthorizer;

impl Authorizer for AutoAuthorizer {
    fn authorize(&self, _: &str, _: SafetyClassification, level: AuthorizationLevel) -> Result<bool> {
        Ok(level == AuthorizationLevel::Auto)
    }
}
