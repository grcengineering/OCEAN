// Fleet operations for `ocean harden --fleet`.
//
// Multi-target hardening with parallel execution, per-target credential
// isolation, and aggregated results. See ADR-001 and the Sprint 3 design doc.

pub mod executor;
pub mod manifest;

pub use executor::{
    execute_fleet, fleet_exit_code, FleetExecOptions, FleetResult, TargetResult, TargetStatus,
};
pub use manifest::FleetManifest;
