pub mod aws;
pub mod github;
pub mod github_actions;
pub mod github_code_scanning;
pub mod github_dependabot;
pub mod github_repo_security;
pub mod github_secret_scanning;
pub mod github_workflow_permissions;
pub mod mock;
pub mod okta;
pub mod okta_population;

use std::sync::Arc;

use crate::module::registry::Registry;

/// Register all built-in observers into the provided registry.
pub fn register_all(registry: &Registry) {
    registry.register_observer(Arc::new(mock::MockObserver));
    registry.register_observer(Arc::new(mock::MockNetworkObserver));
    registry.register_observer(Arc::new(aws::IamObserver));
    registry.register_observer(Arc::new(github::BranchProtectionObserver));
    registry.register_observer(Arc::new(github_repo_security::RepoSecurityObserver));
    registry.register_observer(Arc::new(github_actions::ActionsPermissionsObserver));
    registry.register_observer(Arc::new(github_dependabot::DependabotAlertsObserver));
    registry.register_observer(Arc::new(github_secret_scanning::SecretScanningAlertsObserver));
    registry.register_observer(Arc::new(github_code_scanning::CodeScanningAlertsObserver));
    registry.register_observer(Arc::new(github_workflow_permissions::WorkflowPermissionsObserver));
    registry.register_observer(Arc::new(okta::MfaPolicyObserver));
    registry.register_observer(Arc::new(okta_population::MfaEnrollmentPopulationObserver));
}
