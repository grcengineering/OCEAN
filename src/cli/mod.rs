pub mod output;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use uuid::Uuid;

use ocean::{
    control::{calculate_uptime, evaluate_control, Control},
    module::{AutoAuthorizer, EnvironmentScope, Executor, Registry, TestConfig},
    modules::{register_all_collectors, register_all_testers},
    scheduler::Schedule,
    storage::{EvidenceQuery, SqliteStore, Store},
};

use output::{print_output, OutputFormat};

// ---------------------------------------------------------------------------
// CLI structure
// ---------------------------------------------------------------------------

/// Open Control Evidence Acquisition Normalizer — "Metasploit for GRC"
#[derive(Parser)]
#[command(
    name = "ocean",
    version,
    about = "Open Control Evidence Acquisition Normalizer"
)]
pub struct Cli {
    /// Path to the SQLite evidence database.
    #[arg(long, env = "OCEAN_DB", global = true, default_value = "")]
    pub db: String,

    /// Output format: json (default) or yaml.
    #[arg(long, global = true, default_value = "json")]
    pub format: String,

    /// Enable verbose output.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Print OCEAN version information.
    Version,

    /// Collect evidence using a collector module.
    Collect {
        /// Module ID (e.g., aws.iam, github.branch_protection).
        module: String,

        /// Skip storing evidence to the database.
        #[arg(long)]
        no_store: bool,
    },

    /// Run an active control test using a tester module.
    #[command(name = "test")]
    Test {
        /// Module ID (e.g., aws.s3_public_access, github.secret_push).
        module: String,

        /// Target environment: production (default), staging, or isolated.
        #[arg(long, default_value = "production")]
        target: String,

        /// Skip storing evidence to the database.
        #[arg(long)]
        no_store: bool,
    },

    /// Manage and inspect registered modules.
    Modules {
        #[command(subcommand)]
        cmd: ModulesCmd,
    },

    /// Evaluate a control against collected evidence.
    Evaluate {
        /// Control ID (e.g., cc6.1).
        control: String,

        /// Custom CEL expression (overrides control YAML).
        #[arg(long)]
        cel: Option<String>,

        /// Directory containing control YAML files.
        #[arg(long, default_value = "controls")]
        controls_dir: String,
    },

    /// Query control evaluation history and uptime.
    History {
        /// Control ID to query.
        #[arg(long)]
        control: String,

        /// Number of days to look back (default: 7).
        #[arg(long, default_value = "7")]
        days: i64,

        /// Start time (RFC3339 or YYYY-MM-DD).
        #[arg(long)]
        from: Option<String>,

        /// End time (RFC3339 or YYYY-MM-DD).
        #[arg(long)]
        to: Option<String>,
    },

    /// Generate a compliance report for a time period.
    Report {
        /// Time period: YYYY-MM-DD:YYYY-MM-DD.
        #[arg(long)]
        period: String,

        /// Report format: json (default), yaml, markdown, csv.
        #[arg(long, default_value = "json")]
        format: String,

        /// Filter to a specific control ID.
        #[arg(long)]
        control: Option<String>,
    },

    /// Manage recurring collection schedules.
    Schedule {
        #[command(subcommand)]
        cmd: ScheduleCmd,
    },

    /// Start the OCEAN REST API server.
    Serve {
        /// TCP port to listen on (default: 8080).
        #[arg(long, default_value = "8080")]
        port: u16,

        /// Bearer token for API authentication.
        #[arg(long, env = "OCEAN_AUTH_TOKEN")]
        auth_token: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum ModulesCmd {
    /// List all registered modules.
    List {
        /// Filter by type: collector or tester.
        #[arg(long = "type")]
        module_type: Option<String>,
    },

    /// Validate a module's metadata and credential requirements.
    Validate {
        /// Module ID to validate (e.g., aws.iam).
        id: String,
    },
}

#[derive(Subcommand)]
pub enum ScheduleCmd {
    /// Create a new recurring schedule.
    Add {
        /// Associate schedule with a control ID.
        #[arg(long)]
        control: Option<String>,

        /// Cron expression (e.g., "0 * * * *" for hourly).
        #[arg(long)]
        cron: String,

        /// Comma-separated list of module IDs to run.
        #[arg(long, value_delimiter = ',')]
        modules: Vec<String>,

        /// Maximum safety level allowed: safe (default), observable, reversible, destructive.
        #[arg(long, default_value = "safe")]
        max_safety: String,

        /// Target environment: production (default), staging, isolated.
        #[arg(long, name = "env", default_value = "production")]
        environment: String,

        /// Enable this schedule immediately (default: true).
        #[arg(long, default_value = "true")]
        enabled: bool,

        /// Run missed windows when the scheduler catches up.
        #[arg(long)]
        catch_up: bool,
    },

    /// List all schedules.
    List,

    /// Remove a schedule by ID.
    Remove {
        /// Schedule ID to remove.
        id: String,
    },

    /// Show recent run history for a schedule.
    Status {
        /// Schedule ID.
        id: String,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let format = OutputFormat::from_str(&cli.format);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    match cli.command {
        Commands::Version => cmd_version(&mut out, format),
        Commands::Collect { module, no_store } => {
            cmd_collect(&mut out, format, &cli.db, &module, !no_store)
        }
        Commands::Test {
            module,
            target,
            no_store,
        } => cmd_test(&mut out, format, &cli.db, &module, &target, !no_store),
        Commands::Modules { cmd } => match cmd {
            ModulesCmd::List { module_type } => {
                cmd_modules_list(&mut out, format, module_type.as_deref())
            }
            ModulesCmd::Validate { id } => cmd_modules_validate(&mut out, format, &id),
        },
        Commands::Evaluate {
            control,
            cel,
            controls_dir,
        } => cmd_evaluate(
            &mut out,
            format,
            &cli.db,
            &control,
            cel.as_deref(),
            &controls_dir,
        ),
        Commands::History {
            control,
            days,
            from,
            to,
        } => cmd_history(
            &mut out,
            format,
            &cli.db,
            &control,
            days,
            from.as_deref(),
            to.as_deref(),
        ),
        Commands::Report {
            period,
            format: rep_fmt,
            control,
        } => cmd_report(&mut out, &cli.db, &period, &rep_fmt, control.as_deref()),
        Commands::Schedule { cmd } => match cmd {
            ScheduleCmd::Add {
                control,
                cron,
                modules,
                max_safety,
                environment,
                enabled,
                catch_up,
            } => cmd_schedule_add(
                &mut out,
                format,
                &cli.db,
                control.as_deref(),
                &cron,
                &modules,
                &max_safety,
                &environment,
                enabled,
                catch_up,
            ),
            ScheduleCmd::List => cmd_schedule_list(&mut out, format, &cli.db),
            ScheduleCmd::Remove { id } => cmd_schedule_remove(&cli.db, &id),
            ScheduleCmd::Status { id } => cmd_schedule_status(&mut out, format, &cli.db, &id),
        },
        Commands::Serve { port, auth_token } => {
            let db_path = resolve_db_path(&cli.db);
            cmd_serve(port, auth_token.as_deref(), &db_path)
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the database path: flag > OCEAN_DB env > ~/.ocean/evidence.db.
fn resolve_db_path(db: &str) -> String {
    if !db.is_empty() {
        return db.to_string();
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    format!("{home}/.ocean/evidence.db")
}

fn open_store(db: &str) -> Result<SqliteStore> {
    let path = resolve_db_path(db);
    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create database directory: {parent:?}"))?;
    }
    SqliteStore::open(&path)
}

fn build_registry() -> Arc<Registry> {
    let registry = Arc::new(Registry::new());
    register_all_collectors(&registry);
    register_all_testers(&registry);
    registry
}

/// Collect all environment variables as the module config HashMap.
fn env_as_config() -> HashMap<String, String> {
    std::env::vars().collect()
}

fn parse_env_scope(s: &str) -> Result<EnvironmentScope> {
    match s.to_lowercase().as_str() {
        "production" | "prod" => Ok(EnvironmentScope::Production),
        "staging" | "stage" => Ok(EnvironmentScope::Staging),
        "isolated" | "lab" => Ok(EnvironmentScope::Isolated),
        other => Err(anyhow!(
            "unknown environment scope '{other}'; expected: production, staging, isolated"
        )),
    }
}

fn parse_date(s: &str) -> Result<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    let nd = NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .with_context(|| format!("parse date '{s}'; expected RFC3339 or YYYY-MM-DD"))?;
    Ok(nd.and_hms_opt(0, 0, 0).unwrap().and_utc())
}

fn load_control(
    control_id: &str,
    controls_dir: &str,
    cel_override: Option<&str>,
) -> Result<Control> {
    // Support both flat (controls/mock.mfa_enforcement.yaml) and
    // namespaced (controls/mock/mfa_enforcement.yaml) layouts.
    let slash_id = control_id.replacen('.', "/", 1);
    let candidates = [
        format!("{controls_dir}/{control_id}.yaml"),
        format!("{controls_dir}/{control_id}.yml"),
        format!("{controls_dir}/{slash_id}.yaml"),
        format!("{controls_dir}/{slash_id}.yml"),
    ];

    let mut yaml_content = String::new();
    let mut found = false;
    for path in &candidates {
        if let Ok(content) = std::fs::read_to_string(path) {
            yaml_content = content;
            found = true;
            break;
        }
    }
    if !found {
        return Err(anyhow!(
            "control file not found for '{control_id}' in directory '{controls_dir}'"
        ));
    }

    let mut control = Control::load_yaml(&yaml_content)
        .with_context(|| format!("parse control YAML for '{control_id}'"))?;

    if let Some(cel) = cel_override {
        control.evaluation_logic.cel_expression = cel.to_string();
        control.evaluation_logic.preset = String::new();
    }

    Ok(control)
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

fn cmd_version<W: Write>(out: &mut W, format: OutputFormat) -> Result<()> {
    let info = serde_json::json!({
        "name": "OCEAN",
        "version": env!("CARGO_PKG_VERSION"),
        "description": env!("CARGO_PKG_DESCRIPTION"),
    });
    print_output(out, &info, format)
}

fn cmd_collect<W: Write>(
    out: &mut W,
    format: OutputFormat,
    db: &str,
    module_id: &str,
    store: bool,
) -> Result<()> {
    let registry = build_registry();
    let executor = Executor::new(registry);
    let config = env_as_config();

    let evidence = executor
        .execute_collector(module_id, &config)
        .with_context(|| format!("execute collector '{module_id}'"))?;

    if store {
        let db_store = open_store(db)?;
        for ev in &evidence {
            db_store
                .store_evidence(ev)
                .with_context(|| format!("store evidence {}", ev.id))?;
        }
    }

    print_output(out, &evidence, format)
}

fn cmd_test<W: Write>(
    out: &mut W,
    format: OutputFormat,
    db: &str,
    module_id: &str,
    target: &str,
    store: bool,
) -> Result<()> {
    let scope = parse_env_scope(target)?;
    let registry = build_registry();
    let executor = Executor::new(registry);
    let config = env_as_config();

    let cfg = TestConfig {
        module_config: config,
        target_environment: scope,
        authorizer: Box::new(AutoAuthorizer),
    };

    let evidence = executor
        .execute_tester(module_id, &cfg)
        .with_context(|| format!("execute tester '{module_id}'"))?;

    if store {
        let db_store = open_store(db)?;
        for ev in &evidence {
            db_store
                .store_evidence(ev)
                .with_context(|| format!("store evidence {}", ev.id))?;
        }
    }

    print_output(out, &evidence, format)
}

fn cmd_modules_list<W: Write>(
    out: &mut W,
    format: OutputFormat,
    module_type: Option<&str>,
) -> Result<()> {
    let registry = build_registry();
    let modules = match module_type {
        Some(t) => registry.list_by_type(t),
        None => registry.list_modules(),
    };
    print_output(out, &modules, format)
}

fn cmd_modules_validate<W: Write>(out: &mut W, format: OutputFormat, id: &str) -> Result<()> {
    let registry = build_registry();
    let info = registry
        .list_modules()
        .into_iter()
        .find(|m| m.id == id)
        .ok_or_else(|| anyhow!("module not found: '{id}'"))?;

    let creds = if info.module_type == "collector" {
        let c = registry.get_collector(id)?;
        c.credential_requirements()
    } else {
        let t = registry.get_tester(id)?;
        t.credential_requirements()
    };

    let result = serde_json::json!({
        "module": info,
        "credential_requirements": creds,
        "valid": true,
    });
    print_output(out, &result, format)
}

fn cmd_evaluate<W: Write>(
    out: &mut W,
    format: OutputFormat,
    db: &str,
    control_id: &str,
    cel: Option<&str>,
    controls_dir: &str,
) -> Result<()> {
    let control = load_control(control_id, controls_dir, cel)?;
    let db_store = open_store(db)?;

    let evidence = db_store.query_evidence(&EvidenceQuery {
        control_id: Some(control_id.to_string()),
        ..Default::default()
    })?;

    let status = evaluate_control(&control, &evidence);
    db_store.store_control_status(&status)?;

    print_output(out, &status, format)
}

fn cmd_history<W: Write>(
    out: &mut W,
    format: OutputFormat,
    db: &str,
    control_id: &str,
    days: i64,
    from: Option<&str>,
    to: Option<&str>,
) -> Result<()> {
    let now = Utc::now();
    let to_time = match to {
        Some(s) => parse_date(s)?,
        None => now,
    };
    let from_time = match from {
        Some(s) => parse_date(s)?,
        None => now - Duration::days(days),
    };

    let db_store = open_store(db)?;
    let statuses = db_store.query_history(control_id, from_time, to_time)?;
    let uptime = calculate_uptime(control_id, from_time, to_time, &statuses);

    let result = serde_json::json!({
        "control_id": control_id,
        "from": from_time.to_rfc3339(),
        "to": to_time.to_rfc3339(),
        "uptime": uptime,
        "history": statuses,
    });
    print_output(out, &result, format)
}

fn cmd_report<W: Write>(
    out: &mut W,
    db: &str,
    period: &str,
    format: &str,
    control_filter: Option<&str>,
) -> Result<()> {
    let parts: Vec<&str> = period.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(anyhow!(
            "invalid --period '{period}'; expected YYYY-MM-DD:YYYY-MM-DD"
        ));
    }
    let from_time = parse_date(parts[0])?;
    let to_time = parse_date(parts[1])?;

    let db_store = open_store(db)?;
    let evidence = db_store.query_evidence(&EvidenceQuery {
        control_id: control_filter.map(|s| s.to_string()),
        from_time: Some(from_time),
        to_time: Some(to_time),
        ..Default::default()
    })?;

    match format.to_lowercase().as_str() {
        "markdown" | "md" => {
            writeln!(out, "# OCEAN Compliance Report")?;
            writeln!(out)?;
            writeln!(
                out,
                "**Period:** {} — {}",
                from_time.format("%Y-%m-%d"),
                to_time.format("%Y-%m-%d")
            )?;
            writeln!(out, "**Evidence count:** {}", evidence.len())?;
            if let Some(c) = control_filter {
                writeln!(out, "**Control:** {c}")?;
            }
            writeln!(out)?;
            writeln!(out, "## Evidence")?;
            writeln!(out)?;
            writeln!(out, "| ID | Module | Status | Time |")?;
            writeln!(out, "|---|---|---|---|")?;
            for ev in &evidence {
                writeln!(
                    out,
                    "| {} | {} | {} | {} |",
                    &ev.id.to_string()[..8],
                    ev.metadata.module.name,
                    ev.status,
                    ev.time.format("%Y-%m-%d %H:%M"),
                )?;
            }
        }
        "csv" => {
            writeln!(out, "id,module,status,time")?;
            for ev in &evidence {
                writeln!(
                    out,
                    "{},{},{},{}",
                    ev.id,
                    ev.metadata.module.name,
                    ev.status,
                    ev.time.to_rfc3339(),
                )?;
            }
        }
        _ => {
            let report = serde_json::json!({
                "period": {
                    "from": from_time.to_rfc3339(),
                    "to": to_time.to_rfc3339(),
                },
                "control_filter": control_filter,
                "evidence_count": evidence.len(),
                "evidence": evidence,
            });
            let fmt = OutputFormat::from_str(format);
            print_output(out, &report, fmt)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_schedule_add<W: Write>(
    out: &mut W,
    format: OutputFormat,
    db: &str,
    control: Option<&str>,
    cron: &str,
    modules: &[String],
    max_safety: &str,
    environment: &str,
    enabled: bool,
    catch_up: bool,
) -> Result<()> {
    let now = Utc::now();
    let schedule = Schedule {
        id: Uuid::new_v4().to_string(),
        control_id: control.unwrap_or("").to_string(),
        cron_expr: cron.to_string(),
        modules: modules.to_vec(),
        max_safety_level: max_safety.to_string(),
        environment_scope: environment.to_string(),
        enabled,
        catch_up,
        last_run: None,
        next_run: None,
        created_at: now,
        updated_at: now,
    };

    let db_store = open_store(db)?;
    db_store.store_schedule(&schedule)?;

    print_output(out, &schedule, format)
}

fn cmd_schedule_list<W: Write>(out: &mut W, format: OutputFormat, db: &str) -> Result<()> {
    let db_store = open_store(db)?;
    let schedules = db_store.list_schedules()?;
    print_output(out, &schedules, format)
}

fn cmd_schedule_remove(db: &str, id: &str) -> Result<()> {
    let db_store = open_store(db)?;
    db_store.delete_schedule(id)?;
    eprintln!("schedule '{id}' removed");
    Ok(())
}

fn cmd_schedule_status<W: Write>(
    out: &mut W,
    format: OutputFormat,
    db: &str,
    id: &str,
) -> Result<()> {
    let db_store = open_store(db)?;
    let schedule = db_store.get_schedule(id)?;
    let runs = db_store.list_schedule_runs(id, 10)?;
    let result = serde_json::json!({
        "schedule": schedule,
        "recent_runs": runs,
    });
    print_output(out, &result, format)
}

fn cmd_serve(port: u16, auth_token: Option<&str>, db: &str) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(ocean::api::server::serve(
        port,
        auth_token.map(String::from),
        db.to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- resolve_db_path ---

    #[test]
    fn resolve_db_path_explicit() {
        assert_eq!(resolve_db_path("/tmp/test.db"), "/tmp/test.db");
    }

    #[test]
    fn resolve_db_path_empty_uses_default() {
        let path = resolve_db_path("");
        assert!(
            path.ends_with("/.ocean/evidence.db")
                || path.ends_with("\\.ocean\\evidence.db")
                || path.ends_with("/.ocean/evidence.db")
        );
        assert!(path.contains(".ocean"));
    }

    // --- parse_env_scope ---

    #[test]
    fn parse_env_scope_production() {
        assert!(matches!(
            parse_env_scope("production"),
            Ok(EnvironmentScope::Production)
        ));
        assert!(matches!(
            parse_env_scope("prod"),
            Ok(EnvironmentScope::Production)
        ));
    }

    #[test]
    fn parse_env_scope_staging() {
        assert!(matches!(
            parse_env_scope("staging"),
            Ok(EnvironmentScope::Staging)
        ));
        assert!(matches!(
            parse_env_scope("stage"),
            Ok(EnvironmentScope::Staging)
        ));
    }

    #[test]
    fn parse_env_scope_isolated() {
        assert!(matches!(
            parse_env_scope("isolated"),
            Ok(EnvironmentScope::Isolated)
        ));
        assert!(matches!(
            parse_env_scope("lab"),
            Ok(EnvironmentScope::Isolated)
        ));
    }

    #[test]
    fn parse_env_scope_invalid() {
        assert!(parse_env_scope("unknown").is_err());
        assert!(parse_env_scope("").is_err());
    }

    // --- parse_date ---

    #[test]
    fn parse_date_rfc3339() {
        let dt = parse_date("2024-01-15T00:00:00Z").unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2024-01-15");
    }

    #[test]
    fn parse_date_yyyy_mm_dd() {
        let dt = parse_date("2024-06-01").unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2024-06-01");
    }

    #[test]
    fn parse_date_invalid() {
        assert!(parse_date("not-a-date").is_err());
        assert!(parse_date("2024-13-01").is_err()); // month 13
    }

    // --- cmd_version ---

    #[test]
    fn cmd_version_json() {
        let mut buf = Vec::new();
        cmd_version(&mut buf, OutputFormat::Json).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("\"name\""));
        assert!(s.contains("OCEAN"));
        assert!(s.contains("\"version\""));
    }

    #[test]
    fn cmd_version_yaml() {
        let mut buf = Vec::new();
        cmd_version(&mut buf, OutputFormat::Yaml).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("name"));
        assert!(s.contains("OCEAN"));
    }

    // --- cmd_modules_list ---

    #[test]
    fn cmd_modules_list_all() {
        let mut buf = Vec::new();
        cmd_modules_list(&mut buf, OutputFormat::Json, None).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let modules: serde_json::Value = serde_json::from_str(&s).unwrap();
        // 9 modules registered: 5 collectors + 4 testers (mock.test is tester, mock.network is collector)
        assert!(modules.as_array().unwrap().len() >= 9);
    }

    #[test]
    fn cmd_modules_list_collectors_only() {
        let mut buf = Vec::new();
        cmd_modules_list(&mut buf, OutputFormat::Json, Some("collector")).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let modules: serde_json::Value = serde_json::from_str(&s).unwrap();
        let arr = modules.as_array().unwrap();
        assert!(!arr.is_empty());
        for m in arr {
            assert_eq!(m["module_type"].as_str().unwrap(), "collector");
        }
    }

    #[test]
    fn cmd_modules_list_testers_only() {
        let mut buf = Vec::new();
        cmd_modules_list(&mut buf, OutputFormat::Json, Some("tester")).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let modules: serde_json::Value = serde_json::from_str(&s).unwrap();
        let arr = modules.as_array().unwrap();
        assert!(!arr.is_empty());
        for m in arr {
            assert_eq!(m["module_type"].as_str().unwrap(), "tester");
        }
    }

    // --- cmd_modules_validate ---

    #[test]
    fn cmd_modules_validate_known_module() {
        let mut buf = Vec::new();
        cmd_modules_validate(&mut buf, OutputFormat::Json, "aws.iam").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("aws.iam"));
        assert!(s.contains("\"valid\""));
        assert!(s.contains("true"));
    }

    #[test]
    fn cmd_modules_validate_unknown_module() {
        let mut buf = Vec::new();
        let err =
            cmd_modules_validate(&mut buf, OutputFormat::Json, "nonexistent.module").unwrap_err();
        assert!(err.to_string().contains("module not found"));
    }

    // --- cmd_modules_validate collector vs tester ---

    #[test]
    fn cmd_modules_validate_tester() {
        let mut buf = Vec::new();
        cmd_modules_validate(&mut buf, OutputFormat::Json, "mock.safety_test").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("mock.safety_test"));
    }

    // --- load_control ---

    #[test]
    fn load_control_missing_file() {
        let err = load_control("nonexistent.ctrl", "/tmp/no_such_dir", None).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn load_control_cel_override() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let ctrl_path = dir.join("test_ctrl.yaml");
        let yaml = r#"
id: test_ctrl
name: Test Control
description: Test
evaluation_logic:
  preset: all_effective
"#;
        std::fs::write(&ctrl_path, yaml).unwrap();
        let dir_str = dir.to_str().unwrap();

        let control = load_control("test_ctrl", dir_str, Some("evidence.size() > 0")).unwrap();
        assert_eq!(
            control.evaluation_logic.cel_expression,
            "evidence.size() > 0"
        );
        assert!(control.evaluation_logic.preset.is_empty());

        let _ = std::fs::remove_file(ctrl_path);
    }

    // --- cmd_collect + cmd_test with in-memory store ---

    #[test]
    fn cmd_collect_mock_no_store() {
        let mut buf = Vec::new();
        // mock.test collector exists, no store so no DB needed
        let result = cmd_collect(&mut buf, OutputFormat::Json, "", "mock.test", false);
        assert!(result.is_ok(), "collect failed: {:?}", result);
        let s = String::from_utf8(buf).unwrap();
        let ev: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(ev.as_array().unwrap().len() >= 1);
    }

    #[test]
    fn cmd_collect_unknown_module() {
        let mut buf = Vec::new();
        let err = cmd_collect(&mut buf, OutputFormat::Json, "", "nope.unknown", false).unwrap_err();
        assert!(err.to_string().contains("nope.unknown"));
    }

    #[test]
    fn cmd_test_mock_no_store() {
        let mut buf = Vec::new();
        let result = cmd_test(
            &mut buf,
            OutputFormat::Json,
            "",
            "mock.safety_test",
            "production",
            false,
        );
        assert!(result.is_ok(), "test failed: {:?}", result);
        let s = String::from_utf8(buf).unwrap();
        let ev: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(ev.as_array().unwrap().len() >= 1);
    }

    #[test]
    fn cmd_test_invalid_target() {
        let mut buf = Vec::new();
        let err = cmd_test(
            &mut buf,
            OutputFormat::Json,
            "",
            "mock.safety_test",
            "invalid_env",
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown environment scope"));
    }

    // --- cmd_report period parsing ---

    #[test]
    fn cmd_report_invalid_period() {
        let mut buf = Vec::new();
        let err = cmd_report(&mut buf, "", "2024-01-01", "json", None).unwrap_err();
        assert!(err.to_string().contains("invalid --period"));
    }

    // --- cmd_serve ---
    // NOTE: cmd_serve binds a real TCP port, so we don't call it in unit tests.
    // It is exercised by the integration smoke test (`ocean serve` via CLI).

    // --- cmd_history + cmd_evaluate with SQLite ---

    #[test]
    fn cmd_history_empty_db() {
        let dir = std::env::temp_dir();
        let db_path = dir
            .join(format!("ocean_test_hist_{}.db", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string();
        let mut buf = Vec::new();
        let result = cmd_history(
            &mut buf,
            OutputFormat::Json,
            &db_path,
            "cc6.1",
            7,
            None,
            None,
        );
        assert!(result.is_ok());
        let s = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["control_id"].as_str().unwrap(), "cc6.1");
        assert_eq!(v["history"].as_array().unwrap().len(), 0);
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn cmd_schedule_add_list_remove_roundtrip() {
        let dir = std::env::temp_dir();
        let db_path = dir
            .join(format!("ocean_test_sched_{}.db", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string();

        let modules = vec!["aws.iam".to_string()];

        // Add
        let mut buf = Vec::new();
        cmd_schedule_add(
            &mut buf,
            OutputFormat::Json,
            &db_path,
            Some("cc6.1"),
            "0 * * * *",
            &modules,
            "safe",
            "production",
            true,
            false,
        )
        .unwrap();
        let s = String::from_utf8(buf).unwrap();
        let sched: serde_json::Value = serde_json::from_str(&s).unwrap();
        let sched_id = sched["id"].as_str().unwrap().to_string();
        assert!(!sched_id.is_empty());

        // List
        let mut buf2 = Vec::new();
        cmd_schedule_list(&mut buf2, OutputFormat::Json, &db_path).unwrap();
        let s2 = String::from_utf8(buf2).unwrap();
        let list: serde_json::Value = serde_json::from_str(&s2).unwrap();
        assert_eq!(list.as_array().unwrap().len(), 1);

        // Remove
        cmd_schedule_remove(&db_path, &sched_id).unwrap();

        // List again — empty
        let mut buf3 = Vec::new();
        cmd_schedule_list(&mut buf3, OutputFormat::Json, &db_path).unwrap();
        let s3 = String::from_utf8(buf3).unwrap();
        let list3: serde_json::Value = serde_json::from_str(&s3).unwrap();
        assert_eq!(list3.as_array().unwrap().len(), 0);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn cmd_collect_and_evaluate_roundtrip() {
        use std::io::Write as _;

        let dir = std::env::temp_dir();
        let db_path = dir
            .join(format!("ocean_test_eval_{}.db", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string();

        // Write a minimal control YAML
        let ctrl_dir = dir.join(format!("ctrl_dir_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&ctrl_dir).unwrap();
        let ctrl_yaml = r#"
id: mock.ctrl
name: Mock Control
description: Integration test control
evaluation_logic:
  preset: all_effective
"#;
        std::fs::write(ctrl_dir.join("mock.ctrl.yaml"), ctrl_yaml).unwrap();
        let ctrl_dir_str = ctrl_dir.to_str().unwrap();

        // Collect
        let mut buf = Vec::new();
        cmd_collect(&mut buf, OutputFormat::Json, &db_path, "mock.test", true).unwrap();

        // Evaluate
        let mut buf2 = Vec::new();
        cmd_evaluate(
            &mut buf2,
            OutputFormat::Json,
            &db_path,
            "mock.ctrl",
            None,
            ctrl_dir_str,
        )
        .unwrap();
        let s2 = String::from_utf8(buf2).unwrap();
        let status: serde_json::Value = serde_json::from_str(&s2).unwrap();
        assert!(status["status"].as_str().is_some());

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_dir_all(&ctrl_dir);
    }

    // --- report ---

    #[test]
    fn cmd_report_empty_db_json() {
        let dir = std::env::temp_dir();
        let db_path = dir
            .join(format!("ocean_test_report_{}.db", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string();
        let mut buf = Vec::new();
        cmd_report(&mut buf, &db_path, "2024-01-01:2024-12-31", "json", None).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["evidence_count"].as_i64().unwrap(), 0);
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn cmd_report_markdown_format() {
        let dir = std::env::temp_dir();
        let db_path = dir
            .join(format!("ocean_test_report_md_{}.db", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string();
        let mut buf = Vec::new();
        cmd_report(
            &mut buf,
            &db_path,
            "2024-01-01:2024-12-31",
            "markdown",
            None,
        )
        .unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("# OCEAN Compliance Report"));
        assert!(s.contains("**Period:**"));
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn cmd_report_csv_format() {
        let dir = std::env::temp_dir();
        let db_path = dir
            .join(format!("ocean_test_report_csv_{}.db", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string();
        let mut buf = Vec::new();
        cmd_report(&mut buf, &db_path, "2024-01-01:2024-12-31", "csv", None).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.starts_with("id,module,status,time"));
        let _ = std::fs::remove_file(&db_path);
    }
}
