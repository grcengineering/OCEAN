#![no_main]
//! Fuzz target for check YAML loading (CheckDefinition deserialization).
//!
//! Feeds arbitrary strings into serde_yaml deserialization of CheckDefinition
//! to find panics or pathological behavior in the check definition parser.

use libfuzzer_sys::fuzz_target;
use ocean::check::CheckDefinition;

fuzz_target!(|data: &[u8]| {
    // Attempt to parse as UTF-8 first — serde_yaml operates on str.
    if let Ok(yaml_str) = std::str::from_utf8(data) {
        // Deserialize arbitrary YAML into CheckDefinition.
        // Errors are expected; we are looking for panics/hangs.
        let _ = serde_yaml::from_str::<CheckDefinition>(yaml_str);
    }

    // Also test the from_slice path directly for non-UTF-8 robustness.
    let _ = serde_yaml::from_slice::<CheckDefinition>(data);
});
