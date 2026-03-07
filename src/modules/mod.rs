pub mod github_common;
pub mod observers;
pub mod testers;

use crate::module::registry::Registry;

/// Register all built-in observers into the provided registry.
pub fn register_all_observers(registry: &Registry) {
    observers::register_all(registry);
}

/// Register all built-in testers into the provided registry.
pub fn register_all_testers(registry: &Registry) {
    testers::register_all(registry);
}
