pub mod collectors;
pub mod testers;

use crate::module::registry::Registry;

/// Register all built-in collectors into the provided registry.
pub fn register_all_collectors(registry: &Registry) {
    collectors::register_all(registry);
}

/// Register all built-in testers into the provided registry.
pub fn register_all_testers(registry: &Registry) {
    testers::register_all(registry);
}
