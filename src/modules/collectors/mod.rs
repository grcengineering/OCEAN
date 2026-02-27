pub mod aws;
pub mod github;
pub mod mock;
pub mod okta;

use std::sync::Arc;

use crate::module::registry::Registry;

/// Register all built-in collectors into the provided registry.
pub fn register_all(registry: &Registry) {
    registry.register_collector(Arc::new(mock::MockCollector));
    registry.register_collector(Arc::new(mock::MockNetworkCollector));
    registry.register_collector(Arc::new(aws::IamCollector));
    registry.register_collector(Arc::new(github::BranchProtectionCollector));
    registry.register_collector(Arc::new(okta::MfaPolicyCollector));
}
