// OCEAN — Open Control Evidence Assessment Normalizer
//
// Public SDK re-exports. Import `ocean::*` to access all core types.

pub mod api;
pub mod check;
pub mod codegen;
pub mod config;
pub mod control;
pub mod dashboard;
pub mod eval;
pub mod evidence;
pub mod fleet;
pub mod harden;
pub mod module;
pub mod report;
pub mod modules;
pub mod scheduler;
pub mod secrets;
pub mod storage;

pub use evidence::{ConfidenceLevel, Evidence, StatusId};
pub use module::{Observer, Module, Registry, Tester};

#[cfg(test)]
pub mod testutil;
