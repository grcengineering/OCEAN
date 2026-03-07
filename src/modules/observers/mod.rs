pub mod aws;
pub mod azure;
pub mod github;
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
    registry.register_observer(Arc::new(azure::ConditionalAccessObserver));
    registry.register_observer(Arc::new(github::BranchProtectionObserver));
    registry.register_observer(Arc::new(okta::MfaPolicyObserver));
    registry.register_observer(Arc::new(okta_population::MfaEnrollmentPopulationObserver));
}
