pub mod aws;
pub mod azure;
pub mod github;
pub mod github_action_pin_audit;
pub mod github_actions_restriction;
pub mod github_branch_bypass;
pub mod github_unsigned_commit;
pub mod github_workflow_injection;
pub mod mock;
pub mod okta;
pub mod okta_admin_ip_restriction;
pub mod okta_default_policy_bypass;
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
    registry.register_tester(Arc::new(
        okta_admin_ip_restriction::AdminIpRestrictionTester,
    ));
    registry.register_tester(Arc::new(
        okta_default_policy_bypass::DefaultPolicyBypassTester,
    ));
    registry.register_tester(Arc::new(okta_pr_mfa_downgrade::PrMfaDowngradeTester));
    registry.register_tester(Arc::new(
        github_actions_restriction::ActionsRestrictionTester,
    ));
    registry.register_tester(Arc::new(github_unsigned_commit::UnsignedCommitTester));
    registry.register_tester(Arc::new(github_workflow_injection::WorkflowInjectionTester));
    registry.register_tester(Arc::new(github_action_pin_audit::ActionPinAuditTester));
}
