// Module system — pluggable observers and testers.

pub mod executor;
pub mod observer;
pub mod registry;
pub mod safety;
pub mod tester;
pub mod validation;

pub use executor::{Executor, TestConfig};
pub use observer::Observer;
pub use registry::{ModuleInfo, Registry};
pub use safety::{
    AuthorizationLevel, Authorizer, AutoAuthorizer, ConfirmAuthorizer, EnvironmentScope,
    SafetyClassification,
};
pub use tester::Tester;

use serde::{Deserialize, Serialize};

/// Base trait for all OCEAN modules (observers and testers).
pub trait Module: Send + Sync {
    /// Unique identifier (e.g., "aws.iam", "github.secret_push").
    fn id(&self) -> &str;
    /// Human-readable name.
    fn name(&self) -> &str;
    /// Semantic version of this module.
    fn version(&self) -> &str;
    /// Name of the external system this module interacts with.
    fn source_system(&self) -> &str;
    /// OCSF class UIDs that this module can produce.
    fn evidence_types(&self) -> &[i32];
    /// Credentials this module requires to operate.
    fn credential_requirements(&self) -> Vec<CredentialReq>;
}

/// Describes a single credential that a module requires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialReq {
    pub name: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub description: String,
    pub required: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_req_serde_round_trip() {
        let req = CredentialReq {
            name: "AWS_ACCESS_KEY_ID".to_string(),
            cred_type: "env".to_string(),
            description: "AWS access key".to_string(),
            required: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\""));
        let decoded: CredentialReq = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, req.name);
        assert_eq!(decoded.cred_type, req.cred_type);
        assert!(decoded.required);
    }

    #[test]
    fn credential_req_optional_not_required() {
        let req = CredentialReq {
            name: "OPTIONAL_KEY".to_string(),
            cred_type: "env".to_string(),
            description: "Optional key".to_string(),
            required: false,
        };
        assert!(!req.required);
    }
}
