// CEL evaluation engine.

pub mod engine;
pub mod presets;

pub use engine::CelEngine;
pub use presets::{all_effective, any_effective, active_verified};
