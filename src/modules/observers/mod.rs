pub mod aws;
pub mod azure;
pub mod github;
pub mod github_actions;
pub mod github_actions_allowed;
pub mod github_audit_log_streaming;
pub mod github_code_scanning;
pub mod github_commit_signing;
pub mod github_copilot_governance;
pub mod github_dependabot;
pub mod github_dependency_review;
pub mod github_environment_protection;
pub mod github_installed_apps;
pub mod github_oauth_apps;
pub mod github_oidc_config;
pub mod github_org_admin_audit;
pub mod github_org_base_permissions;
pub mod github_org_mfa;
pub mod github_org_rulesets;
pub mod github_pat_policy;
pub mod github_repo_security;
pub mod github_runner_config;
pub mod github_saml_sso;
pub mod github_secret_scanning;
pub mod github_security_config;
pub mod github_workflow_permissions;
pub mod mock;
pub mod okta;
pub mod okta_admin_roles;
pub mod okta_authenticators;
pub mod okta_behavior_detection;
pub mod okta_network_zones;
pub mod okta_oauth_app_policy;
pub mod okta_password_policy;
pub mod okta_population;
pub mod okta_recovery_policy;
pub mod okta_session_policy;
pub mod okta_system_log_streaming;
pub mod okta_threat_insight;

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
    registry.register_observer(Arc::new(
        github_secret_scanning::SecretScanningAlertsObserver,
    ));
    registry.register_observer(Arc::new(github_code_scanning::CodeScanningAlertsObserver));
    registry.register_observer(Arc::new(
        github_workflow_permissions::WorkflowPermissionsObserver,
    ));
    registry.register_observer(Arc::new(azure::ConditionalAccessObserver));
    registry.register_observer(Arc::new(okta::MfaPolicyObserver));
    registry.register_observer(Arc::new(okta_population::MfaEnrollmentPopulationObserver));
    registry.register_observer(Arc::new(okta_password_policy::PasswordPolicyObserver));
    registry.register_observer(Arc::new(okta_session_policy::SessionPolicyObserver));
    registry.register_observer(Arc::new(okta_recovery_policy::RecoveryPolicyObserver));
    registry.register_observer(Arc::new(okta_threat_insight::ThreatInsightObserver));
    registry.register_observer(Arc::new(
        okta_system_log_streaming::SystemLogStreamingObserver,
    ));
    registry.register_observer(Arc::new(okta_behavior_detection::BehaviorDetectionObserver));
    registry.register_observer(Arc::new(okta_authenticators::AuthenticatorsObserver));
    registry.register_observer(Arc::new(okta_admin_roles::AdminRolesObserver));
    registry.register_observer(Arc::new(okta_network_zones::NetworkZonesObserver));
    registry.register_observer(Arc::new(okta_oauth_app_policy::OAuthAppPolicyObserver));
    registry.register_observer(Arc::new(github_org_mfa::OrgMfaEnforcementObserver));
    registry.register_observer(Arc::new(
        github_org_base_permissions::OrgBasePermissionsObserver,
    ));
    registry.register_observer(Arc::new(github_org_admin_audit::OrgAdminAuditObserver));
    registry.register_observer(Arc::new(github_saml_sso::SamlSsoObserver));
    registry.register_observer(Arc::new(github_pat_policy::PatPolicyObserver));
    registry.register_observer(Arc::new(github_org_rulesets::OrgRulesetsObserver));
    registry.register_observer(Arc::new(github_commit_signing::CommitSigningObserver));
    registry.register_observer(Arc::new(github_actions_allowed::ActionsAllowedObserver));
    registry.register_observer(Arc::new(github_runner_config::RunnerConfigObserver));
    registry.register_observer(Arc::new(
        github_environment_protection::EnvironmentProtectionObserver,
    ));
    registry.register_observer(Arc::new(github_oidc_config::OidcConfigObserver));
    registry.register_observer(Arc::new(github_oauth_apps::OAuthAppsObserver));
    registry.register_observer(Arc::new(github_installed_apps::InstalledAppsObserver));
    registry.register_observer(Arc::new(github_dependency_review::DependencyReviewObserver));
    registry.register_observer(Arc::new(
        github_audit_log_streaming::AuditLogStreamingObserver,
    ));
    registry.register_observer(Arc::new(github_security_config::SecurityConfigObserver));
    registry.register_observer(Arc::new(
        github_copilot_governance::CopilotGovernanceObserver,
    ));
}
