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

#[cfg(test)]
mod tests {
    use super::*;

    // --- SafetyClassification ---

    #[test]
    fn requires_explicit_auth() {
        assert!(!SafetyClassification::Safe.requires_explicit_auth());
        assert!(SafetyClassification::Observable.requires_explicit_auth());
        assert!(SafetyClassification::Reversible.requires_explicit_auth());
        assert!(SafetyClassification::Destructive.requires_explicit_auth());
    }

    #[test]
    fn requires_warning_only_destructive() {
        assert!(!SafetyClassification::Safe.requires_warning());
        assert!(!SafetyClassification::Observable.requires_warning());
        assert!(!SafetyClassification::Reversible.requires_warning());
        assert!(SafetyClassification::Destructive.requires_warning());
    }

    #[test]
    fn safety_classification_display() {
        assert_eq!(SafetyClassification::Safe.to_string(), "safe");
        assert_eq!(SafetyClassification::Observable.to_string(), "observable");
        assert_eq!(SafetyClassification::Reversible.to_string(), "reversible");
        assert_eq!(SafetyClassification::Destructive.to_string(), "destructive");
    }

    #[test]
    fn safety_classification_serde() {
        for sc in [
            SafetyClassification::Safe,
            SafetyClassification::Observable,
            SafetyClassification::Reversible,
            SafetyClassification::Destructive,
        ] {
            let json = serde_json::to_string(&sc).unwrap();
            let decoded: SafetyClassification = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, sc);
        }
    }

    // --- EnvironmentScope ---

    #[test]
    fn environment_scope_display() {
        assert_eq!(EnvironmentScope::Production.to_string(), "production");
        assert_eq!(EnvironmentScope::Staging.to_string(), "staging");
        assert_eq!(EnvironmentScope::Isolated.to_string(), "isolated");
    }

    #[test]
    fn environment_scope_serde() {
        for scope in [EnvironmentScope::Production, EnvironmentScope::Staging, EnvironmentScope::Isolated] {
            let json = serde_json::to_string(&scope).unwrap();
            let decoded: EnvironmentScope = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, scope);
        }
    }

    // --- can_run_in_environment ---

    #[test]
    fn safe_runs_everywhere() {
        for env in [EnvironmentScope::Production, EnvironmentScope::Staging, EnvironmentScope::Isolated] {
            assert!(can_run_in_environment(SafetyClassification::Safe, env));
        }
    }

    #[test]
    fn observable_runs_in_prod_and_staging_not_isolated() {
        assert!(can_run_in_environment(SafetyClassification::Observable, EnvironmentScope::Production));
        assert!(can_run_in_environment(SafetyClassification::Observable, EnvironmentScope::Staging));
        assert!(!can_run_in_environment(SafetyClassification::Observable, EnvironmentScope::Isolated));
    }

    #[test]
    fn reversible_runs_in_staging_and_isolated_not_prod() {
        assert!(!can_run_in_environment(SafetyClassification::Reversible, EnvironmentScope::Production));
        assert!(can_run_in_environment(SafetyClassification::Reversible, EnvironmentScope::Staging));
        assert!(can_run_in_environment(SafetyClassification::Reversible, EnvironmentScope::Isolated));
    }

    #[test]
    fn destructive_only_in_isolated() {
        assert!(!can_run_in_environment(SafetyClassification::Destructive, EnvironmentScope::Production));
        assert!(!can_run_in_environment(SafetyClassification::Destructive, EnvironmentScope::Staging));
        assert!(can_run_in_environment(SafetyClassification::Destructive, EnvironmentScope::Isolated));
    }

    // --- enforce_scope ---

    #[test]
    fn enforce_scope_allowed_passes() {
        assert!(enforce_scope("t1", SafetyClassification::Safe, EnvironmentScope::Production).is_ok());
    }

    #[test]
    fn enforce_scope_denied_returns_error() {
        let err = enforce_scope("t1", SafetyClassification::Destructive, EnvironmentScope::Production).unwrap_err();
        assert!(err.to_string().contains("scope violation"));
    }

    // --- highest_safety_classification ---

    #[test]
    fn highest_of_empty_is_safe() {
        assert_eq!(highest_safety_classification(&[]), SafetyClassification::Safe);
    }

    #[test]
    fn highest_of_single() {
        assert_eq!(
            highest_safety_classification(&[SafetyClassification::Reversible]),
            SafetyClassification::Reversible
        );
    }

    #[test]
    fn highest_picks_most_restrictive() {
        let classes = [
            SafetyClassification::Safe,
            SafetyClassification::Reversible,
            SafetyClassification::Observable,
        ];
        assert_eq!(highest_safety_classification(&classes), SafetyClassification::Reversible);
    }

    #[test]
    fn highest_with_destructive_wins() {
        let classes = [SafetyClassification::Reversible, SafetyClassification::Destructive];
        assert_eq!(highest_safety_classification(&classes), SafetyClassification::Destructive);
    }

    // --- required_auth_level ---

    #[test]
    fn required_auth_level_mapping() {
        assert_eq!(required_auth_level(SafetyClassification::Safe), AuthorizationLevel::Auto);
        assert_eq!(required_auth_level(SafetyClassification::Observable), AuthorizationLevel::Prompt);
        assert_eq!(required_auth_level(SafetyClassification::Reversible), AuthorizationLevel::Explicit);
        assert_eq!(required_auth_level(SafetyClassification::Destructive), AuthorizationLevel::Warning);
    }

    // --- AuthorizationLevel Display ---

    #[test]
    fn auth_level_display() {
        assert_eq!(AuthorizationLevel::Auto.to_string(), "auto");
        assert_eq!(AuthorizationLevel::Prompt.to_string(), "prompt");
        assert_eq!(AuthorizationLevel::Explicit.to_string(), "explicit");
        assert_eq!(AuthorizationLevel::Warning.to_string(), "warning");
    }

    // --- AutoAuthorizer ---

    #[test]
    fn auto_authorizer_approves_auto_level() {
        let auth = AutoAuthorizer;
        assert!(auth.authorize("t", SafetyClassification::Safe, AuthorizationLevel::Auto).unwrap());
    }

    #[test]
    fn auto_authorizer_rejects_non_auto() {
        let auth = AutoAuthorizer;
        assert!(!auth.authorize("t", SafetyClassification::Observable, AuthorizationLevel::Prompt).unwrap());
        assert!(!auth.authorize("t", SafetyClassification::Reversible, AuthorizationLevel::Explicit).unwrap());
        assert!(!auth.authorize("t", SafetyClassification::Destructive, AuthorizationLevel::Warning).unwrap());
    }
}
