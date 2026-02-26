// OCEAN — Open Control Evidence Acquisition Normalizer
//
// Public SDK re-exports. Import `ocean::*` to access all core types.

pub mod evidence;
pub mod module;
pub mod storage;
pub mod eval;
pub mod control;
pub mod scheduler;
pub mod secrets;
pub mod api;
pub mod config;
pub mod modules;

pub use evidence::{Evidence, ConfidenceLevel, StatusId};
pub use module::{Module, Collector, Tester, Registry};

#[cfg(test)]
pub mod testutil;
