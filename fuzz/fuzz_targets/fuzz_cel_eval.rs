#![no_main]
//! Fuzz target for CEL expression evaluation.
//!
//! Feeds arbitrary strings as CEL expressions into cel's
//! compile + execute pipeline to find panics, excessive memory use,
//! or stack overflows in expression parsing and evaluation.

use libfuzzer_sys::fuzz_target;
use cel::{Context, Program};

fuzz_target!(|data: &[u8]| {
    let expr = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Phase 1: Compile the expression. Most fuzz inputs will fail here.
    let program = match Program::compile(expr) {
        Ok(p) => p,
        Err(_) => return,
    };

    // Phase 2: Execute with a context containing typical OCEAN variable types.
    // This exercises the evaluator with representative data shapes.
    let mut ctx = Context::default();

    // Add variables matching common OCEAN check extraction patterns.
    let _ = ctx.add_variable("status_code", 200_i64);
    let _ = ctx.add_variable("mfa", true);
    let _ = ctx.add_variable("count", 42_i64);
    let _ = ctx.add_variable("name", "fuzz-test");
    let _ = ctx.add_variable("enabled", false);
    let _ = ctx.add_variable("length", 10_i64);
    let _ = ctx.add_variable("items", vec![1_i64, 2, 3]);

    // Execute — errors are expected; we are looking for panics/hangs.
    let _ = program.execute(&ctx);
});
