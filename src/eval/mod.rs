// CEL evaluation engine.

pub mod engine;
pub mod presets;

pub use engine::CelEngine;
pub use presets::{active_verified, all_effective, any_effective};
