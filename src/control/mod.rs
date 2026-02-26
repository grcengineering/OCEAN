// Control definitions, evaluator, composite, and framework support.
pub mod definition;
pub mod evaluator;
pub mod composite;
pub mod framework;

pub use definition::{Control, ControlStatus, UptimeResult, EvaluationLogic, FrameworkMapping};
pub use evaluator::{evaluate_control, calculate_uptime};
pub use composite::{ComponentResult, evaluate_composite};
pub use framework::{Framework, FrameworkControl};
