// Control definitions, evaluator, composite, and framework support.
pub mod composite;
pub mod definition;
pub mod evaluator;
pub mod framework;

pub use composite::{
    evaluate_composite, evaluate_composite_with_components, ComponentResult, CrossCheckResult,
};
pub use definition::{
    ComponentSpec, Control, ControlStatus, CrossCheck, CrossCheckAssertion, EvaluationLogic,
    ExportSpec, FrameworkMapping, ModuleRef, UptimeResult,
};
pub use evaluator::{calculate_uptime, evaluate_control};
pub use framework::{Framework, FrameworkControl};
