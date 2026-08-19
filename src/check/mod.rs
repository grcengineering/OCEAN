// check — .check.yaml runtime infrastructure.
//
// Provides the definition structs, runtime interpreter, and file loader
// for OCEAN's YAML-based check format.

pub mod definition;
pub mod interpreter;
pub mod loader;

pub use definition::{CheckDefinition, CheckType};
pub use interpreter::{YamlObserver, YamlTester};
pub use loader::{
    load_all_checks, load_check_file, load_checks_from_dir, load_definitions_from_dir,
    register_check,
};
