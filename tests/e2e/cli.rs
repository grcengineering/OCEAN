use std::process::Command;
use tempfile::TempDir;

fn ocean() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ocean"))
}

// 1. ocean version — assert exit 0
#[test]
fn e2e_version() {
    let status = ocean()
        .arg("version")
        .status()
        .expect("failed to run ocean version");
    assert!(status.success(), "ocean version exited with: {status}");
}

// 2. ocean --db <tmp>/db observe mock.test --no-store --format json
//    assert exit 0, parse stdout as JSON value
#[test]
fn e2e_observe_no_store() {
    let dir = TempDir::new().expect("tempdir");
    let db = dir.path().join("evidence.db");

    let output = ocean()
        .args([
            "--db",
            db.to_str().unwrap(),
            "--format",
            "json",
            "observe",
            "mock.test",
            "--no-store",
        ])
        .output()
        .expect("failed to run ocean observe");

    assert!(
        output.status.success(),
        "observe exited non-zero: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let _parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout is not valid JSON");
}

// 3. ocean --db <tmp>/db observe does.not.exist --no-store — assert exit != 0
#[test]
fn e2e_observe_unknown_module() {
    let dir = TempDir::new().expect("tempdir");
    let db = dir.path().join("evidence.db");

    let status = ocean()
        .args([
            "--db",
            db.to_str().unwrap(),
            "observe",
            "does.not.exist",
            "--no-store",
        ])
        .status()
        .expect("failed to run ocean observe");

    assert!(
        !status.success(),
        "expected non-zero exit for unknown module, got: {status}"
    );
}

// 4. ocean --db <tmp>/db history --control mock.mfa_enforcement --format json
//    assert exit 0, stdout starts with '['
#[test]
fn e2e_history_empty() {
    let dir = TempDir::new().expect("tempdir");
    let db = dir.path().join("evidence.db");

    let output = ocean()
        .args([
            "--db",
            db.to_str().unwrap(),
            "--format",
            "json",
            "history",
            "--control",
            "mock.mfa_enforcement",
        ])
        .output()
        .expect("failed to run ocean history");

    assert!(
        output.status.success(),
        "history exited non-zero: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("history stdout is not valid JSON");
    // history returns an object with a "history" array field; for an empty db it should be empty
    let history = parsed.get("history").expect("missing 'history' field");
    assert!(
        history.is_array(),
        "expected 'history' field to be an array, got: {history}"
    );
    assert_eq!(
        history.as_array().unwrap().len(),
        0,
        "expected empty history array for fresh db"
    );
}

// 5. schedule add then list — verify the entry shows up in list output
#[test]
fn e2e_schedule_add_and_list() {
    let dir = TempDir::new().expect("tempdir");
    let db = dir.path().join("evidence.db");
    let db_str = db.to_str().unwrap();

    // Add a schedule
    let add_output = ocean()
        .args([
            "--db",
            db_str,
            "schedule",
            "add",
            "--modules",
            "mock.test",
            "--cron",
            "0 * * * *",
        ])
        .output()
        .expect("failed to run ocean schedule add");

    assert!(
        add_output.status.success(),
        "schedule add exited non-zero: {}\nstderr: {}",
        add_output.status,
        String::from_utf8_lossy(&add_output.stderr)
    );

    // List schedules
    let list_output = ocean()
        .args(["--db", db_str, "--format", "json", "schedule", "list"])
        .output()
        .expect("failed to run ocean schedule list");

    assert!(
        list_output.status.success(),
        "schedule list exited non-zero: {}\nstderr: {}",
        list_output.status,
        String::from_utf8_lossy(&list_output.stderr)
    );

    let stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(
        stdout.contains("mock.test"),
        "expected 'mock.test' in schedule list output, got: {stdout}"
    );
}
