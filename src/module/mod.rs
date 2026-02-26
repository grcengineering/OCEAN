// Module system — pluggable collectors and testers.

pub mod collector;
pub mod tester;
pub mod registry;
pub mod safety;
pub mod executor;
pub mod validation;

pub use collector::Collector;
pub use tester::Tester;
pub use registry::{Registry, ModuleInfo};
pub use safety::{SafetyClassification, EnvironmentScope, AuthorizationLevel, Authorizer, AutoAuthorizer};
pub use executor::{Executor, TestConfig};

use serde::{Deserialize, Serialize};

/// Base trait for all OCEAN modules (collectors and testers).
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
