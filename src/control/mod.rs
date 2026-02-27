// Control definitions, evaluator, composite, and framework support.
pub mod composite;
pub mod definition;
pub mod evaluator;
pub mod framework;

pub use composite::{evaluate_composite, ComponentResult};
pub use definition::{Control, ControlStatus, EvaluationLogic, FrameworkMapping, UptimeResult};
pub use evaluator::{calculate_uptime, evaluate_control};
pub use framework::{Framework, FrameworkControl};
