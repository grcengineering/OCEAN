pub mod aws;
pub mod azure;
pub mod github;
pub mod github_branch_bypass;
pub mod mock;
pub mod okta;
pub mod okta_pr_mfa_downgrade;

use std::sync::Arc;

use crate::module::registry::Registry;

/// Register all built-in testers into the provided registry.
pub fn register_all(registry: &Registry) {
    registry.register_tester(Arc::new(azure::MfaBypassTester));
    registry.register_tester(Arc::new(mock::MockTester));
    registry.register_tester(Arc::new(aws::S3PublicAccessTester));
    registry.register_tester(Arc::new(github::SecretPushTester));
    registry.register_tester(Arc::new(github_branch_bypass::BranchBypassTester));
    registry.register_tester(Arc::new(okta::MfaBypassTester));
    registry.register_tester(Arc::new(okta_pr_mfa_downgrade::PrMfaDowngradeTester));
}
