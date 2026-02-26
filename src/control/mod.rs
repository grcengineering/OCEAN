// Control definitions and evaluator — evaluator/composite/framework implemented in Phase 3.
pub mod definition;
pub mod evaluator;
pub mod composite;
pub mod framework;

pub use definition::{Control, ControlStatus, UptimeResult, EvaluationLogic, FrameworkMapping};
