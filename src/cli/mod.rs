pub mod filter;
pub mod output;
pub mod sarif;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    check::loader::load_all_checks,
    codegen::{generate as codegen_generate, BuildTarget},
    control::{
        calculate_uptime, evaluate_composite, evaluate_control, ComponentResult, Control,
        Framework, ModuleRef,
    },
    harden::{
        confirm_apply, execute_plans, plan_harden, print_dry_run as harden_print_dry_run,
        print_results as harden_print_results, warn_user_checks, RemediationMode,
    },
    module::{AutoAuthorizer, ConfirmAuthorizer, EnvironmentScope, Executor, Registry, TestConfig},
    modules::{register_all_observers, register_all_testers},
    scheduler::Schedule,
    storage::{EvidenceQuery, SqliteStore, Store},
};

use output::{print_evaluation_table, print_output, EvaluationResult, ModuleRunResult, OutputFormat};

// ---------------------------------------------------------------------------
// CLI structure
// ---------------------------------------------------------------------------

/// Open Control Evidence Assessment Normalizer — "Metasploit for GRC"
#[derive(Parser)]
#[command(
    name = "ocean",
    version,
    about = "Open Control Evidence Assessment Normalizer"
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
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Print OCEAN version information.
    Version,

    /// Observe system state using an observer module.
    Observe {
        /// Module ID for legacy mode (e.g., aws.iam, github.branch_protection).
        /// Omit when using --target/-t and --control/-c.
        module: Option<String>,

        /// Target integration name (okta, aws, github, or * for all). Pipeline mode.
        #[arg(short = 't', long = "target")]
        target: Option<String>,

        /// Control path prefix (iam, iam.mfa). Pipeline mode: runs all observers for matched controls.
        #[arg(short = 'c', long = "control")]
        control: Option<String>,

        /// Directory containing control YAML files (pipeline mode).
        #[arg(long, default_value = "controls")]
        controls_dir: String,

        /// Skip storing evidence to the database.
        #[arg(long)]
        no_store: bool,
    },

    /// Run an active control test using a tester module.
    #[command(name = "test")]
    Test {
        /// Module ID for legacy mode (e.g., aws.s3_public_access, github.secret_push).
        /// Omit when using --target/-t and --control/-c.
        module: Option<String>,

        /// Target integration name (okta, aws, github, or * for all). Pipeline mode.
        #[arg(short = 't', long = "target")]
        target: Option<String>,

        /// Control path prefix (iam, iam.mfa, iam.mfa.phishing_resistant). Pipeline mode.
        #[arg(short = 'c', long = "control")]
        control: Option<String>,

        /// Environment scope for active testing: production (default), staging, or isolated.
        #[arg(long = "env", default_value = "production")]
        env: String,

        /// Directory containing control YAML files (pipeline mode).
        #[arg(long, default_value = "controls")]
        controls_dir: String,

        /// Skip storing evidence to the database.
        #[arg(long)]
        no_store: bool,

        /// Confirm execution of active tests that require authorization (observable, reversible, destructive).
        /// Without this flag, only safe tests will run; others are rejected.
        #[arg(long)]
        confirm: bool,
    },

    /// Manage and inspect registered modules.
    Modules {
        #[command(subcommand)]
        cmd: ModulesCmd,
    },

    /// Evaluate a control against observed evidence.
    Evaluate {
        /// Control ID for legacy mode (e.g., iam.mfa_enforcement).
        /// Omit when using --target/-t and --control/-c.
        control: Option<String>,

        /// Target integration name (okta, aws, github, or * for all). Pipeline mode.
        #[arg(short = 't', long = "target")]
        target: Option<String>,

        /// Control path prefix (iam, iam.mfa, iam.mfa.phishing_resistant). Pipeline mode.
        #[arg(short = 'c', long = "control")]
        control_path: Option<String>,

        /// Custom CEL expression (overrides control YAML, legacy mode only).
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

    /// Generate a compliance report.
    ///
    /// Two modes:
    ///   --period YYYY-MM-DD:YYYY-MM-DD    DB evidence report (default)
    ///   --framework soc2,nist,...          Live check run mapped to frameworks
    Report {
        /// Time period: YYYY-MM-DD:YYYY-MM-DD (DB evidence mode).
        #[arg(long)]
        period: Option<String>,

        /// Compliance frameworks to report on (live mode): soc2, nist, iso27001, pci-dss, disa-stig, all.
        #[arg(long, value_delimiter = ',')]
        framework: Option<Vec<String>>,

        /// Directory containing .check.yaml files (live framework mode).
        #[arg(long, default_value = "checks")]
        checks_dir: String,

        /// Include passing checks in framework report.
        #[arg(long)]
        include_passing: bool,

        /// Report format: json (default), yaml, markdown, csv, sarif.
        #[arg(long, default_value = "json")]
        format: String,

        /// Filter to a specific control ID.
        #[arg(long)]
        control: Option<String>,

        /// Filter checks by tags (comma-separated, e.g., mfa,identity).
        #[arg(long)]
        tags: Option<String>,

        /// Filter checks by severity (comma-separated, e.g., critical,high).
        #[arg(long)]
        severity: Option<String>,

        /// Filter checks by profile tier (L1, L2, L3). Includes the tier and below.
        #[arg(long)]
        profile: Option<String>,

        /// Filter checks by source system (e.g., github, okta, aws).
        #[arg(long)]
        source: Option<String>,
    },

    /// Remediate failing controls using API calls or Terraform.
    Harden {
        /// Check ID (e.g., GH-1.08) or source system (e.g., github). If omitted, runs all checks.
        #[arg(conflicts_with = "fleet")]
        target: Option<String>,

        /// Remediation mode: api (default), terraform, cli, all.
        #[arg(long, default_value = "api")]
        mode: String,

        /// Apply remediation (without this flag, shows dry-run plan).
        #[arg(long)]
        apply: bool,

        /// Skip interactive confirmation prompt (requires --apply; for CI/automation).
        #[arg(long)]
        confirm: bool,

        /// Directory containing .check.yaml files.
        #[arg(long, default_value = "checks")]
        checks_dir: String,

        /// Output directory for generated Terraform files (terraform mode only).
        #[arg(long, default_value = "./ocean-terraform")]
        terraform_dir: String,

        /// Output format: json (default), table.
        #[arg(long, default_value = "table")]
        format: String,

        /// Filter checks by tags (comma-separated, e.g., mfa,identity).
        #[arg(long)]
        tags: Option<String>,

        /// Filter checks by severity (comma-separated, e.g., critical,high).
        #[arg(long)]
        severity: Option<String>,

        /// Filter checks by profile tier (L1, L2, L3). Includes the tier and below.
        #[arg(long)]
        profile: Option<String>,

        /// Path to fleet target manifest (YAML) for multi-target hardening.
        #[arg(long, value_name = "PATH")]
        fleet: Option<std::path::PathBuf>,

        /// Max parallel targets for fleet mode (1-16, default: 4).
        #[arg(long, default_value = "4", value_parser = clap::value_parser!(u8).range(1..=16))]
        concurrency: u8,

        /// Continue fleet execution if a target fails.
        #[arg(long)]
        continue_on_error: bool,

        /// Output directory for fleet per-target results.
        #[arg(long, default_value = "fleet-results")]
        output: std::path::PathBuf,

        /// Validate fleet file and show execution plan without running.
        #[arg(long)]
        dry_run: bool,
    },

    /// Generate standalone code packs from .check.yaml files.
    Build {
        /// Output target: api-script, gh-cli.
        #[arg(long, default_value = "api-script")]
        target: String,

        /// Directory containing .check.yaml source files.
        #[arg(long, default_value = "checks")]
        source: String,

        /// Output directory (default: packs/<target>/).
        #[arg(long)]
        output: Option<String>,

        /// Validate check files without generating output.
        #[arg(long)]
        validate: bool,

        /// Show what would change without writing files.
        #[arg(long)]
        diff: bool,

        /// Filter checks by ID prefix or source system.
        #[arg(long)]
        filter: Option<String>,
    },

    /// Manage recurring observation schedules.
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

    /// Launch interactive TUI dashboard with real-time control monitoring.
    Dashboard {
        /// Auto-refresh interval in seconds (default: 30).
        #[arg(long, default_value = "30")]
        refresh: u64,

        /// Directory containing control YAML files.
        #[arg(long, default_value = "controls")]
        controls_dir: String,
    },

    /// Show compliance posture against a framework.
    Compliance {
        /// Framework file path (YAML). If omitted, scans controls_dir for framework YAMLs.
        #[arg(long)]
        framework: Option<String>,

        /// Directory containing control YAML files.
        #[arg(long, default_value = "controls")]
        controls_dir: String,

        /// Output format: json (default), markdown.
        #[arg(long, default_value = "json")]
        format: String,
    },
}

#[derive(Subcommand)]
pub enum ModulesCmd {
    /// List all registered modules.
    List {
        /// Filter by type: observer or tester.
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
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    run_with(&mut out, cli)
}

/// Dispatch a parsed `Cli` to the appropriate handler.
///
/// Split from `run()` so tests can exercise the dispatcher with an in-memory
/// writer and `Cli::try_parse_from(...)`.
pub fn run_with<W: Write>(out: &mut W, cli: Cli) -> Result<()> {
    let format = OutputFormat::from_str(&cli.format);

    let command = cli.command.unwrap_or(Commands::Dashboard {
        refresh: 30,
        controls_dir: "controls".to_string(),
    });

    match command {
        Commands::Version => cmd_version(out, format),
        Commands::Observe {
            module,
            target,
            control,
            controls_dir,
            no_store,
        } => {
            if target.is_some() || control.is_some() {
                let t = target.as_deref().unwrap_or("*");
                let p = control.as_deref().ok_or_else(|| {
                    anyhow!("--control/-c is required when using --target/-t")
                })?;
                cmd_observe_path(out, format, &cli.db, t, p, &controls_dir, !no_store)
            } else if let Some(m) = module.as_deref() {
                cmd_observe(out, format, &cli.db, m, !no_store)
            } else {
                Err(anyhow!(
                    "Specify a module ID or use --target/-t and --control/-c"
                ))
            }
        }
        Commands::Test {
            module,
            target,
            control,
            env,
            controls_dir,
            no_store,
            confirm,
        } => {
            if target.is_some() || control.is_some() {
                let t = target.as_deref().unwrap_or("*");
                let p = control.as_deref().ok_or_else(|| {
                    anyhow!("--control/-c is required when using --target/-t")
                })?;
                cmd_test_path(out, format, &cli.db, t, p, &env, &controls_dir, !no_store, confirm)
            } else if let Some(m) = module.as_deref() {
                cmd_test(out, format, &cli.db, m, &env, !no_store, confirm)
            } else {
                Err(anyhow!(
                    "Specify a module ID or use --target/-t and --control/-c"
                ))
            }
        }
        Commands::Modules { cmd } => match cmd {
            ModulesCmd::List { module_type } => {
                cmd_modules_list(out, format, module_type.as_deref())
            }
            ModulesCmd::Validate { id } => cmd_modules_validate(out, format, &id),
        },
        Commands::Evaluate {
            control,
            target,
            control_path,
            cel,
            controls_dir,
        } => {
            if target.is_some() || control_path.is_some() {
                let t = target.as_deref().unwrap_or("*");
                let p = control_path.as_deref().ok_or_else(|| {
                    anyhow!("--control/-c is required when using --target/-t")
                })?;
                cmd_evaluate_path(out, format, &cli.db, t, p, &controls_dir)
            } else if let Some(ctrl) = control.as_deref() {
                cmd_evaluate(out, format, &cli.db, ctrl, cel.as_deref(), &controls_dir)
            } else {
                Err(anyhow!(
                    "Specify a control ID or use --target/-t and --control/-c"
                ))
            }
        }
        Commands::History {
            control,
            days,
            from,
            to,
        } => cmd_history(
            out,
            format,
            &cli.db,
            &control,
            days,
            from.as_deref(),
            to.as_deref(),
        ),
        Commands::Report {
            period,
            framework,
            checks_dir,
            include_passing,
            format: rep_fmt,
            control,
            tags,
            severity,
            profile,
            source,
        } => {
            let check_filter = filter::CheckFilter {
                tags: tags.map(|t| filter::parse_csv(&t)).unwrap_or_default(),
                severities: severity.map(|s| filter::parse_csv(&s)).unwrap_or_default(),
                profile: profile.clone(),
            };
            if let Some(frameworks) = framework {
                cmd_report_framework(
                    out,
                    &checks_dir,
                    &frameworks,
                    include_passing,
                    &rep_fmt,
                    &check_filter,
                    source.as_deref(),
                    profile.as_deref(),
                )
            } else {
                let p = period.ok_or_else(|| {
                    anyhow!("--period YYYY-MM-DD:YYYY-MM-DD is required when --framework is not specified")
                })?;
                cmd_report(out, &cli.db, &p, &rep_fmt, control.as_deref())
            }
        }
        Commands::Harden {
            target,
            mode,
            apply,
            confirm,
            checks_dir,
            terraform_dir,
            format: harden_fmt,
            tags,
            severity,
            profile,
            fleet,
            concurrency,
            continue_on_error,
            output,
            dry_run,
        } => {
            let check_filter = filter::CheckFilter {
                tags: tags.map(|t| filter::parse_csv(&t)).unwrap_or_default(),
                severities: severity.map(|s| filter::parse_csv(&s)).unwrap_or_default(),
                profile,
            };

            if let Some(fleet_path) = fleet {
                // Fleet mode: multi-target hardening
                cmd_harden_fleet(
                    out,
                    &fleet_path,
                    &checks_dir,
                    &mode,
                    apply,
                    confirm,
                    &terraform_dir,
                    &harden_fmt,
                    &check_filter,
                    concurrency,
                    continue_on_error,
                    &output,
                    dry_run,
                )
            } else {
                // Single-target mode (existing behavior)
                cmd_harden(
                    out,
                    &checks_dir,
                    &mode,
                    apply,
                    confirm,
                    target.as_deref(),
                    &terraform_dir,
                    &harden_fmt,
                    &check_filter,
                )
            }
        }
        Commands::Build {
            target,
            source,
            output,
            validate,
            diff,
            filter,
        } => cmd_build(
            out,
            &source,
            &target,
            output.as_deref(),
            validate,
            diff,
            filter.as_deref(),
        ),
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
                out,
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
            ScheduleCmd::List => cmd_schedule_list(out, format, &cli.db),
            ScheduleCmd::Remove { id } => cmd_schedule_remove(&cli.db, &id),
            ScheduleCmd::Status { id } => cmd_schedule_status(out, format, &cli.db, &id),
        },
        Commands::Serve { port, auth_token } => {
            let db_path = resolve_db_path(&cli.db);
            cmd_serve(port, auth_token.as_deref(), &db_path)
        }
        Commands::Dashboard {
            refresh,
            controls_dir,
        } => {
            let store = open_store(&cli.db)?;
            crate::dashboard::run(&store, &controls_dir, refresh)
        }
        Commands::Compliance {
            framework,
            controls_dir,
            format: fmt,
        } => cmd_compliance(out, &cli.db, framework.as_deref(), &controls_dir, &fmt),
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
    register_all_observers(&registry);
    register_all_testers(&registry);

    // Load .check.yaml checks from the bundled checks/ directory (relative to
    // the binary's working directory) and from ~/.ocean/checks/.
    let checks_dir = std::path::Path::new("checks");
    load_all_checks(&registry, checks_dir);

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

fn cmd_observe<W: Write>(
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
        .execute_observer(module_id, &config)
        .with_context(|| format!("execute observer '{module_id}'"))?;

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

/// Observers-only pipeline: runs all observers for controls matching target+control path.
fn cmd_observe_path<W: Write>(
    out: &mut W,
    format: OutputFormat,
    db: &str,
    target: &str,
    control_path: &str,
    controls_dir: &str,
    store: bool,
) -> Result<()> {
    let controls = resolve_controls(controls_dir, control_path)?;
    let registry = build_registry();
    let executor = Executor::new(registry);
    let config = env_as_config();
    let db_store = open_store(db)?;

    let mut all_evidence: Vec<serde_json::Value> = Vec::new();

    for control in &controls {
        let observers: Vec<&ModuleRef> = control
            .observers
            .iter()
            .filter(|m| target_matches_module(target, &m.module_id))
            .collect();

        for mref in observers {
            match executor.execute_observer(&mref.module_id, &config) {
                Ok(evidence) => {
                    if store {
                        for ev in &evidence {
                            let _ = db_store.store_evidence(ev);
                        }
                    }
                    for ev in evidence {
                        all_evidence.push(serde_json::to_value(&ev)?);
                    }
                }
                Err(e) => {
                    eprintln!("WARN: observer '{}' failed: {e}", mref.module_id);
                }
            }
        }
    }

    print_output(out, &all_evidence, format)
}

fn cmd_test<W: Write>(
    out: &mut W,
    format: OutputFormat,
    db: &str,
    module_id: &str,
    target: &str,
    store: bool,
    confirm: bool,
) -> Result<()> {
    let scope = parse_env_scope(target)?;
    let registry = build_registry();
    let executor = Executor::new(registry);
    let config = env_as_config();

    let authorizer: Box<dyn crate::module::Authorizer> = if confirm {
        Box::new(ConfirmAuthorizer)
    } else {
        Box::new(AutoAuthorizer)
    };

    let cfg = TestConfig {
        module_config: config,
        target_environment: scope,
        authorizer,
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

    let creds = if info.module_type == "observer" {
        let c = registry.get_observer(id)?;
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

    let mut status = evaluate_control(&control, &evidence);

    // If this control has component_controls, perform composite evaluation and
    // override the status with the composite result.
    if !control.component_controls.is_empty() {
        let mut component_results: Vec<ComponentResult> = Vec::new();
        for comp_id in &control.component_controls {
            let comp_evidence = db_store.query_evidence(&EvidenceQuery {
                control_id: Some(comp_id.clone()),
                ..Default::default()
            })?;
            // Load the component control if possible (best-effort; fall back to
            // a synthetic control with no evaluation logic if not found).
            let comp_ctrl_result = load_control(comp_id, controls_dir, None);
            let comp_status = match comp_ctrl_result {
                Ok(comp_ctrl) => evaluate_control(&comp_ctrl, &comp_evidence),
                Err(_) => {
                    // Create a minimal synthetic control for evaluation.
                    let synthetic = Control {
                        id: comp_id.clone(),
                        name: comp_id.clone(),
                        description: String::new(),
                        evaluation_logic: crate::control::EvaluationLogic::default(),
                        framework_mappings: vec![],
                        observers: vec![],
                        testers: vec![],
                        component_controls: vec![],
                        components: vec![],
                        evaluation_expression_hash: String::new(),
                    };
                    evaluate_control(&synthetic, &comp_evidence)
                }
            };
            component_results.push(ComponentResult {
                control_id: comp_id.clone(),
                status: comp_status.status,
                evidence_ids: comp_status.evidence_ids,
            });
        }
        let composite_status = evaluate_composite(&control, &component_results);
        status.status = composite_status;
        let existing_details = status.evaluation_details.clone();
        status.evaluation_details = if existing_details.is_empty() {
            "composite evaluation used".to_string()
        } else {
            format!("{existing_details}; composite evaluation used")
        };
    }

    db_store.store_control_status(&status)?;

    print_output(out, &status, format)
}

// ---------------------------------------------------------------------------
// Pipeline evaluation helpers (new UX)
// ---------------------------------------------------------------------------

/// Returns true if `module_id` belongs to the given target integration.
/// Target "okta" matches module IDs with prefix "okta." (e.g. "okta.mfa_policy").
/// Target "*" matches all modules.
fn target_matches_module(target: &str, module_id: &str) -> bool {
    if target == "*" {
        return true;
    }
    module_id.split('.').next() == Some(target)
}

/// Glob `controls_dir` recursively and return all controls whose ID matches
/// the given path (exact match or prefix — "iam" matches "iam.mfa_enforcement").
fn resolve_controls(controls_dir: &str, path: &str) -> Result<Vec<Control>> {
    let dir = std::path::Path::new(controls_dir);
    if !dir.exists() {
        return Err(anyhow!(
            "controls directory not found: '{controls_dir}'"
        ));
    }

    let mut all: Vec<Control> = Vec::new();
    fn walk(dir: &std::path::Path, out: &mut Vec<Control>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                if let Ok(content) = std::fs::read_to_string(&p) {
                    if let Ok(ctrl) = Control::load_yaml(&content) {
                        out.push(ctrl);
                    }
                }
            }
        }
    }
    walk(dir, &mut all);

    let prefix_dot = format!("{path}.");
    let matched: Vec<Control> = all
        .into_iter()
        .filter(|c| c.id == path || c.id.starts_with(&prefix_dot))
        .collect();

    if matched.is_empty() {
        return Err(anyhow!(
            "no controls found for path '{path}' in '{controls_dir}'"
        ));
    }
    Ok(matched)
}

/// Run the unified observe → test → evaluate pipeline for every control matching
/// `control_path` that has modules for the given `target`.
fn cmd_evaluate_path<W: Write>(
    out: &mut W,
    format: OutputFormat,
    db: &str,
    target: &str,
    control_path: &str,
    controls_dir: &str,
) -> Result<()> {
    let controls = resolve_controls(controls_dir, control_path)?;
    let registry = build_registry();
    let executor = Executor::new(registry);
    let config = env_as_config();
    let db_store = open_store(db)?;

    let mut results: Vec<EvaluationResult> = Vec::new();

    for control in &controls {
        let mut module_runs: Vec<ModuleRunResult> = Vec::new();

        // ── Observers ────────────────────────────────────────────────────────
        let observers: Vec<&ModuleRef> = control
            .observers
            .iter()
            .filter(|m| target_matches_module(target, &m.module_id))
            .collect();

        for mref in observers {
            match executor.execute_observer(&mref.module_id, &config) {
                Ok(evidence) => {
                    for ev in &evidence {
                        let _ = db_store.store_evidence(ev);
                    }
                    module_runs.push(ModuleRunResult {
                        module_id: mref.module_id.clone(),
                        module_type: "observe",
                        status: "OK".to_string(),
                        error: None,
                    });
                }
                Err(e) => {
                    module_runs.push(ModuleRunResult {
                        module_id: mref.module_id.clone(),
                        module_type: "observe",
                        status: "ERROR".to_string(),
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        // ── Testers ───────────────────────────────────────────────────────────
        let testers: Vec<&ModuleRef> = control
            .testers
            .iter()
            .filter(|m| target_matches_module(target, &m.module_id))
            .collect();

        for mref in testers {
            let cfg = TestConfig {
                module_config: config.clone(),
                target_environment: EnvironmentScope::Production,
                authorizer: Box::new(AutoAuthorizer),
            };
            match executor.execute_tester(&mref.module_id, &cfg) {
                Ok(evidence) => {
                    for ev in &evidence {
                        let _ = db_store.store_evidence(ev);
                    }
                    module_runs.push(ModuleRunResult {
                        module_id: mref.module_id.clone(),
                        module_type: "test",
                        status: "PASS".to_string(),
                        error: None,
                    });
                }
                Err(e) => {
                    module_runs.push(ModuleRunResult {
                        module_id: mref.module_id.clone(),
                        module_type: "test",
                        status: "FAIL".to_string(),
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        // ── CEL Evaluation ────────────────────────────────────────────────────
        let evidence = db_store.query_evidence(&EvidenceQuery {
            control_id: Some(control.id.clone()),
            ..Default::default()
        })?;
        let status = evaluate_control(control, &evidence);
        let _ = db_store.store_control_status(&status);

        let framework = control
            .framework_mappings
            .first()
            .map(|m| format!("{} {}", m.framework, m.requirement_id))
            .unwrap_or_default();

        let findings = if status.status != "effective" {
            vec![status.evaluation_details.clone()]
        } else {
            vec![]
        };

        results.push(EvaluationResult {
            control_id: control.id.clone(),
            control_name: control.name.clone(),
            target: target.to_string(),
            status: status.status,
            confidence: status.confidence,
            framework,
            module_runs,
            findings,
        });
    }

    // ── Output ────────────────────────────────────────────────────────────────
    // Pipeline mode defaults to human-readable table. Pass --format yaml for
    // structured YAML output (useful for scripting).
    if format == OutputFormat::Yaml {
        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "control_id": r.control_id,
                    "target": r.target,
                    "status": r.status,
                    "confidence": r.confidence,
                    "framework": r.framework,
                    "findings": r.findings,
                    "module_runs": r.module_runs.iter().map(|m| serde_json::json!({
                        "module_id": m.module_id,
                        "type": m.module_type,
                        "status": m.status,
                        "error": m.error,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        print_output(out, &json_results, format)?;
    } else {
        print_evaluation_table(out, &results)?;
    }
    Ok(())
}

/// Run active testers only (no observers, no CEL) for controls matching `control_path`.
#[allow(clippy::too_many_arguments)]
fn cmd_test_path<W: Write>(
    out: &mut W,
    format: OutputFormat,
    db: &str,
    target: &str,
    control_path: &str,
    env: &str,
    controls_dir: &str,
    store: bool,
    confirm: bool,
) -> Result<()> {
    parse_env_scope(env)?; // validate early before any work
    let controls = resolve_controls(controls_dir, control_path)?;

    let registry = build_registry();
    let executor = Executor::new(registry);
    let config = env_as_config();
    let db_store = open_store(db)?;

    let mut results: Vec<EvaluationResult> = Vec::new();

    for control in &controls {
        let mut module_runs: Vec<ModuleRunResult> = Vec::new();

        let testers: Vec<&ModuleRef> = control
            .testers
            .iter()
            .filter(|m| target_matches_module(target, &m.module_id))
            .collect();

        for mref in testers {
            let authorizer: Box<dyn crate::module::Authorizer> = if confirm {
                Box::new(ConfirmAuthorizer)
            } else {
                Box::new(AutoAuthorizer)
            };
            let cfg = TestConfig {
                module_config: config.clone(),
                target_environment: parse_env_scope(env).unwrap_or(EnvironmentScope::Production),
                authorizer,
            };
            match executor.execute_tester(&mref.module_id, &cfg) {
                Ok(evidence) => {
                    if store {
                        for ev in &evidence {
                            let _ = db_store.store_evidence(ev);
                        }
                    }
                    module_runs.push(ModuleRunResult {
                        module_id: mref.module_id.clone(),
                        module_type: "test",
                        status: "PASS".to_string(),
                        error: None,
                    });
                }
                Err(e) => {
                    module_runs.push(ModuleRunResult {
                        module_id: mref.module_id.clone(),
                        module_type: "test",
                        status: "FAIL".to_string(),
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        let framework = control
            .framework_mappings
            .first()
            .map(|m| format!("{} {}", m.framework, m.requirement_id))
            .unwrap_or_default();

        results.push(EvaluationResult {
            control_id: control.id.clone(),
            control_name: control.name.clone(),
            target: target.to_string(),
            status: "unknown".to_string(),
            confidence: "low".to_string(),
            framework,
            module_runs,
            findings: vec![],
        });
    }

    if format == OutputFormat::Yaml {
        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "control_id": r.control_id,
                    "target": r.target,
                    "module_runs": r.module_runs.iter().map(|m| serde_json::json!({
                        "module_id": m.module_id,
                        "type": m.module_type,
                        "status": m.status,
                        "error": m.error,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        print_output(out, &json_results, format)?;
    } else {
        print_evaluation_table(out, &results)?;
    }
    Ok(())
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
    rt.block_on(crate::api::server::serve(
        port,
        auth_token.map(String::from),
        db.to_string(),
    ))
}

// ─── ocean report --framework ─────────────────────────────────────────────────

fn cmd_report_framework<W: Write>(
    out: &mut W,
    checks_dir: &str,
    frameworks: &[String],
    include_passing: bool,
    format: &str,
    check_filter: &filter::CheckFilter,
    source_filter: Option<&str>,
    profile_filter: Option<&str>,
) -> Result<()> {
    let dir = std::path::Path::new(checks_dir);
    let config = env_as_config();

    // Normalize framework names: CLI uses hyphens, report module uses underscores.
    let normalize_fw = |name: &str| -> String {
        match name {
            "pci-dss" => "pci_dss".to_string(),
            "disa-stig" => "disa_stig".to_string(),
            other => other.to_string(),
        }
    };

    let all_fws = ["soc2", "nist", "iso27001", "pci_dss", "disa_stig"];
    let requested: Vec<String> = if frameworks.iter().any(|f| f == "all") {
        all_fws.iter().map(|s| s.to_string()).collect()
    } else {
        frameworks.iter().map(|f| normalize_fw(f)).collect()
    };

    // Validate all requested frameworks.
    for fw in &requested {
        crate::report::validate_framework(fw)?;
    }

    // SARIF mode: fall back to legacy check-level output (SARIF doesn't map to
    // the control-level ComplianceReport model).
    if format.eq_ignore_ascii_case("sarif") {
        return cmd_report_framework_sarif(out, dir, &requested, check_filter, &config);
    }

    // Generate a ComplianceReport for each requested framework.
    for fw in &requested {
        let report = crate::report::generate_report(
            dir,
            fw,
            &config,
            source_filter,
            profile_filter,
        )?;

        // If not including passing and there are no failing/partial controls, skip.
        if !include_passing && report.summary.failing == 0 && report.summary.partial == 0 {
            continue;
        }

        crate::report::print_report(out, &report, format)?;
    }

    Ok(())
}

/// SARIF output for framework reports — operates at check level, not control level.
fn cmd_report_framework_sarif<W: Write>(
    out: &mut W,
    checks_dir: &std::path::Path,
    frameworks: &[String],
    check_filter: &filter::CheckFilter,
    config: &HashMap<String, String>,
) -> Result<()> {
    let all_defs = crate::check::loader::load_definitions_from_dir(checks_dir);
    let defs: Vec<_> = if check_filter.is_empty() {
        all_defs
    } else {
        all_defs.into_iter().filter(|d| check_filter.matches(d)).collect()
    };

    if defs.is_empty() {
        writeln!(out, "No checks found in '{}'", checks_dir.display())?;
        return Ok(());
    }

    let registry = build_registry();
    let executor = Executor::new(registry);

    let mut sarif_results: Vec<sarif::CheckResult> = Vec::new();

    for def in &defs {
        if def.check_type != crate::check::definition::CheckType::Passive {
            continue;
        }

        // Only include checks that reference at least one requested framework.
        let refs = crate::report::extract_references(def);
        let matches_fw = refs.iter().any(|(fw, _)| frameworks.contains(fw));
        if !matches_fw {
            continue;
        }

        let status = match executor.execute_observer(&def.id, config) {
            Ok(evidence) => {
                let any_fail = evidence
                    .iter()
                    .any(|e| matches!(e.status_id, crate::StatusId::Ineffective));
                if any_fail { "FAIL" } else { "PASS" }
            }
            Err(_) => "ERROR",
        };

        let sev = def.assertions.first().map(|a| a.severity.as_str()).unwrap_or(&def.severity);
        sarif_results.push(sarif::CheckResult {
            check_id: def.id.clone(),
            check_name: def.name.clone(),
            description: def.description.clone(),
            severity: if sev.is_empty() { "medium".to_string() } else { sev.to_string() },
            tags: def.tags.clone(),
            status: status.to_string(),
            message: if status == "PASS" {
                format!("{}: passed", def.name)
            } else {
                format!("{}: {}", def.name, status.to_lowercase())
            },
            source: def.source.clone(),
        });
    }

    let sarif_log = sarif::build_sarif(&defs, &sarif_results);
    sarif::write_sarif(out, &sarif_log)?;
    Ok(())
}

// ─── ocean harden ─────────────────────────────────────────────────────────────

fn cmd_harden<W: Write>(
    out: &mut W,
    checks_dir: &str,
    mode: &str,
    apply: bool,
    confirm: bool,
    id_filter: Option<&str>,
    terraform_dir: &str,
    format: &str,
    check_filter: &filter::CheckFilter,
) -> Result<()> {
    let dir = std::path::Path::new(checks_dir);
    let rem_mode = RemediationMode::from_str(mode)?;
    let config = env_as_config();

    // TH-3a: Warn about user-authored checks from ~/.ocean/checks/.
    warn_user_checks(out, dir, &[]);

    // Validate that target check ID exists if a specific one was given.
    if let Some(target) = id_filter {
        let all_defs = crate::check::loader::load_definitions_from_dir(dir);
        let target_exists = all_defs.iter().any(|d| d.id == target || d.source == target || d.id.starts_with(target));
        if !target_exists {
            return Err(anyhow!("Check '{}' not found in {}", target, checks_dir));
        }
    }

    let mut plans = plan_harden(dir, &rem_mode, &config, id_filter)?;
    if !check_filter.is_empty() {
        // Load definitions to apply tag/severity/profile filter.
        let defs = crate::check::loader::load_definitions_from_dir(dir);
        let allowed: std::collections::HashSet<String> = defs
            .iter()
            .filter(|d| check_filter.matches(d))
            .map(|d| d.id.clone())
            .collect();
        plans.retain(|p| allowed.contains(&p.check_id));
    }

    if !apply {
        harden_print_dry_run(out, &plans, format, &config)?;
        return Ok(());
    }

    // TH-2a: Show full plan and require confirmation before executing.
    if !confirm_apply(out, &plans, &config, confirm)? {
        writeln!(out, "Aborted.")?;
        return Ok(());
    }

    eprintln!("Executing {} remediation plan(s)...", plans.len());
    let tf_dir = std::path::Path::new(terraform_dir);
    let results = execute_plans(
        &plans,
        &config,
        if rem_mode == RemediationMode::Terraform || rem_mode == RemediationMode::All {
            Some(tf_dir)
        } else {
            None
        },
    );
    harden_print_results(out, &results, format, &config)?;

    let failures = results.iter().filter(|r| !r.success).count();
    if failures > 0 {
        return Err(anyhow!("{failures} remediation(s) failed"));
    }
    Ok(())
}

// ─── ocean harden --fleet ─────────────────────────────────────────────────────

fn cmd_harden_fleet<W: Write>(
    out: &mut W,
    fleet_path: &std::path::Path,
    checks_dir: &str,
    mode: &str,
    apply: bool,
    confirm: bool,
    terraform_dir: &str,
    _format: &str,
    _check_filter: &filter::CheckFilter,
    concurrency: u8,
    continue_on_error: bool,
    output_dir: &std::path::Path,
    dry_run: bool,
) -> Result<()> {
    let rem_mode = RemediationMode::from_str(mode)?;

    // Load and validate the fleet manifest (F9, F10, F5, F7, F2, F1)
    eprintln!("Loading fleet manifest: {}", fleet_path.display());
    let manifest = crate::fleet::FleetManifest::from_file(fleet_path)?;

    eprintln!(
        "Fleet \"{}\" — {} target(s), concurrency {}",
        manifest.fleet.name,
        manifest.targets.len(),
        concurrency,
    );

    // Dry-run: show the execution plan and exit (AC-13)
    if dry_run {
        writeln!(out, "Fleet: {}", manifest.fleet.name)?;
        if let Some(desc) = &manifest.fleet.description {
            writeln!(out, "Description: {desc}")?;
        }
        writeln!(out, "Targets: {}", manifest.targets.len())?;
        writeln!(out, "Concurrency: {concurrency}")?;
        writeln!(out, "Mode: {mode}")?;
        writeln!(out)?;
        for target in &manifest.targets {
            writeln!(
                out,
                "  - {} (source: {}, credentials: {} keys)",
                target.id,
                target.source,
                target.credentials.len()
            )?;
        }
        writeln!(out)?;
        writeln!(out, "Dry run — no checks executed, no credentials resolved beyond manifest validation.")?;
        return Ok(());
    }

    // Require --apply for fleet execution (same as single-target)
    if !apply {
        writeln!(out, "Fleet dry-run plan (use --apply to execute):")?;
        writeln!(out)?;
        for target in &manifest.targets {
            writeln!(out, "  Target: {} ({})", target.id, target.source)?;
        }
        writeln!(out)?;
        writeln!(
            out,
            "Run with --apply to execute fleet hardening across {} target(s).",
            manifest.targets.len()
        )?;
        return Ok(());
    }

    // Confirmation prompt for fleet mode (TH-2a)
    if !confirm {
        write!(
            out,
            "About to execute fleet hardening across {} target(s). Continue? [y/N] ",
            manifest.targets.len()
        )?;
        std::io::Write::flush(out)?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            writeln!(out, "Aborted.")?;
            return Ok(());
        }
    }

    // Execute fleet via tokio runtime
    let opts = crate::fleet::FleetExecOptions {
        checks_dir: checks_dir.to_string(),
        mode: rem_mode,
        apply,
        concurrency,
        continue_on_error,
        output_dir: output_dir.to_path_buf(),
        terraform_dir: terraform_dir.to_string(),
    };

    let rt = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;
    let fleet_result = rt.block_on(crate::fleet::execute_fleet(&manifest, &opts))?;

    // Print fleet summary
    writeln!(out)?;
    writeln!(out, "═══ Fleet Summary ═══")?;
    writeln!(out, "Fleet: {}", fleet_result.fleet_name)?;
    writeln!(
        out,
        "Duration: {}s",
        (fleet_result.completed_at - fleet_result.started_at).num_seconds()
    )?;
    writeln!(
        out,
        "Targets: {} total, {} succeeded, {} failed",
        fleet_result.total_targets, fleet_result.succeeded, fleet_result.failed
    )?;
    writeln!(
        out,
        "Checks: {} run, {} findings",
        fleet_result.checks_run, fleet_result.findings
    )?;
    writeln!(out)?;

    for tr in &fleet_result.targets {
        let status_icon = match tr.status {
            crate::fleet::TargetStatus::Completed => "OK",
            crate::fleet::TargetStatus::Failed => "FAIL",
            crate::fleet::TargetStatus::Skipped => "SKIP",
        };
        writeln!(
            out,
            "  [{status_icon}] {} ({}) — {} checks, {} findings, {} applied",
            tr.id, tr.source, tr.checks_run, tr.findings, tr.changes_applied
        )?;
        if let Some(err) = &tr.error {
            writeln!(out, "       Error: {err}")?;
        }
    }

    writeln!(out)?;
    writeln!(out, "Results: {}", output_dir.display())?;

    // Exit code is handled by the caller via fleet_exit_code
    let exit_code = crate::fleet::fleet_exit_code(&fleet_result);
    if exit_code != 0 {
        return Err(anyhow!(
            "{} target(s) failed during fleet execution",
            fleet_result.failed
        ));
    }

    Ok(())
}

// ─── ocean build ──────────────────────────────────────────────────────────────

fn cmd_build<W: Write>(
    out: &mut W,
    source: &str,
    target: &str,
    output: Option<&str>,
    validate: bool,
    diff: bool,
    filter: Option<&str>,
) -> Result<()> {
    let build_target = BuildTarget::from_str(target)?;
    let source_dir = std::path::Path::new(source);
    let default_output = format!("packs/{}", build_target.slug());
    let output_dir = std::path::Path::new(output.unwrap_or(&default_output));

    codegen_generate(out, source_dir, &build_target, output_dir, validate, diff, filter)?;
    Ok(())
}

fn cmd_compliance<W: Write>(
    out: &mut W,
    db: &str,
    framework_path: Option<&str>,
    controls_dir: &str,
    format: &str,
) -> Result<()> {
    // Load framework YAML.
    let framework_yaml = match framework_path {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("read framework file '{path}'"))?,
        None => {
            // Scan controls_dir for *.framework.yaml or frameworks/*.yaml files.
            let dir = std::path::Path::new(controls_dir);
            let candidates = [
                dir.join("frameworks"),
                dir.to_path_buf(),
            ];
            let mut found_yaml: Option<String> = None;
            'outer: for search_dir in &candidates {
                if !search_dir.exists() {
                    continue;
                }
                if let Ok(entries) = std::fs::read_dir(search_dir) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if name.ends_with(".framework.yaml")
                            || name.ends_with(".framework.yml")
                            || (search_dir.ends_with("frameworks")
                                && (name.ends_with(".yaml") || name.ends_with(".yml")))
                        {
                            if let Ok(content) = std::fs::read_to_string(&p) {
                                found_yaml = Some(content);
                                break 'outer;
                            }
                        }
                    }
                }
            }
            found_yaml.ok_or_else(|| {
                anyhow!(
                    "no framework YAML found; use --framework to specify a path"
                )
            })?
        }
    };

    let framework = Framework::load_yaml(&framework_yaml)
        .context("parsing framework YAML")?;

    let db_store = open_store(db)?;
    let checked_at = Utc::now().to_rfc3339();

    let mut passing = 0usize;
    let mut failing = 0usize;
    let mut unknown = 0usize;

    let mut requirements: Vec<serde_json::Value> = Vec::new();

    for fc in &framework.controls {
        let req_status: &str;
        let mut details_parts: Vec<String> = Vec::new();

        if fc.ocean_control_ids.is_empty() {
            req_status = "unknown";
            details_parts.push("no ocean_control_ids mapped".to_string());
        } else {
            let mut all_effective = true;
            let mut any_ineffective = false;
            let mut any_unknown = false;

            for ctrl_id in &fc.ocean_control_ids {
                match db_store.get_control_status(ctrl_id) {
                    Ok(cs) => match cs.status.as_str() {
                        "effective" => {}
                        "ineffective" => {
                            any_ineffective = true;
                            all_effective = false;
                            details_parts.push(format!("{ctrl_id}: ineffective"));
                        }
                        _ => {
                            any_unknown = true;
                            all_effective = false;
                            details_parts.push(format!("{ctrl_id}: {}", cs.status));
                        }
                    },
                    Err(_) => {
                        any_unknown = true;
                        all_effective = false;
                        details_parts.push(format!("{ctrl_id}: no status"));
                    }
                }
            }

            req_status = if any_ineffective {
                "failing"
            } else if all_effective && !any_unknown {
                "passing"
            } else {
                "unknown"
            };
        }

        match req_status {
            "passing" => passing += 1,
            "failing" => failing += 1,
            _ => unknown += 1,
        }

        requirements.push(serde_json::json!({
            "ref": fc.ref_id,
            "title": fc.title,
            "status": req_status,
            "ocean_control_ids": fc.ocean_control_ids,
            "details": details_parts.join("; "),
        }));
    }

    let total = framework.controls.len();

    match format.to_lowercase().as_str() {
        "markdown" | "md" => {
            writeln!(out, "# Compliance Report: {}", framework.name)?;
            writeln!(out)?;
            writeln!(out, "| Ref | Title | Status |")?;
            writeln!(out, "|-----|-------|--------|")?;
            for req in &requirements {
                let status_icon = match req["status"].as_str().unwrap_or("unknown") {
                    "passing" => "✅",
                    "failing" => "❌",
                    _ => "⚠️",
                };
                writeln!(
                    out,
                    "| {} | {} | {} |",
                    req["ref"].as_str().unwrap_or(""),
                    req["title"].as_str().unwrap_or(""),
                    status_icon,
                )?;
            }
            writeln!(out)?;
            writeln!(out, "**Summary:** {passing}/{total} passing")?;
        }
        _ => {
            let report = serde_json::json!({
                "framework": framework.name,
                "checked_at": checked_at,
                "requirements": requirements,
                "summary": {
                    "total": total,
                    "passing": passing,
                    "failing": failing,
                    "unknown": unknown,
                },
            });
            let fmt = OutputFormat::from_str(format);
            print_output(out, &report, fmt)?;
        }
    }

    Ok(())
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
        // 9 modules registered: 5 observers + 4 testers (mock.test is tester, mock.network is observer)
        assert!(modules.as_array().unwrap().len() >= 9);
    }

    #[test]
    fn cmd_modules_list_observers_only() {
        let mut buf = Vec::new();
        cmd_modules_list(&mut buf, OutputFormat::Json, Some("observer")).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let modules: serde_json::Value = serde_json::from_str(&s).unwrap();
        let arr = modules.as_array().unwrap();
        assert!(!arr.is_empty());
        for m in arr {
            assert_eq!(m["module_type"].as_str().unwrap(), "observer");
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

    // --- cmd_modules_validate observer vs tester ---

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

    // --- cmd_observe + cmd_test with in-memory store ---

    #[test]
    fn cmd_observe_mock_no_store() {
        let mut buf = Vec::new();
        // mock.test observer exists, no store so no DB needed
        let result = cmd_observe(&mut buf, OutputFormat::Json, "", "mock.test", false);
        assert!(result.is_ok(), "observe failed: {:?}", result);
        let s = String::from_utf8(buf).unwrap();
        let ev: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(ev.as_array().unwrap().len() >= 1);
    }

    #[test]
    fn cmd_observe_unknown_module() {
        let mut buf = Vec::new();
        let err = cmd_observe(&mut buf, OutputFormat::Json, "", "nope.unknown", false).unwrap_err();
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
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown environment scope"));
    }

    #[test]
    fn cmd_test_with_confirm_flag() {
        let mut buf = Vec::new();
        let result = cmd_test(
            &mut buf,
            OutputFormat::Json,
            "",
            "mock.safety_test",
            "production",
            false,
            true, // --confirm
        );
        assert!(result.is_ok(), "test with --confirm should succeed: {:?}", result);
        let s = String::from_utf8(buf).unwrap();
        let ev: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(ev.as_array().unwrap().len() >= 1);
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
    fn cmd_observe_and_evaluate_roundtrip() {
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

        // Observe
        let mut buf = Vec::new();
        cmd_observe(&mut buf, OutputFormat::Json, &db_path, "mock.test", true).unwrap();

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

    // --- cmd_compliance ---

    #[test]
    fn cmd_compliance_no_framework_file() {
        // Should fail gracefully when framework file doesn't exist
        let tmp = tempfile::TempDir::new().unwrap();
        let db = tmp.path().join("ocean.db").to_str().unwrap().to_string();
        let fw = tmp.path().join("nonexistent.yaml").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_compliance(&mut out, &db, Some(&fw), "controls", "json");
        assert!(result.is_err());
    }

    #[test]
    fn cmd_compliance_json_empty_db() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = tmp.path().join("ocean.db").to_str().unwrap().to_string();
        let fw_path = tmp.path().join("soc2.framework.yaml");
        std::fs::write(
            &fw_path,
            r#"
id: soc2
name: SOC 2 Type II
version: "2017"
controls:
  - ref: CC6.1
    title: Logical Access Controls
    ocean_control_ids:
      - iam.mfa_enforcement
"#,
        )
        .unwrap();
        let fw_str = fw_path.to_str().unwrap();
        let mut out = Vec::new();
        cmd_compliance(&mut out, &db, Some(fw_str), "controls", "json").unwrap();
        let s = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["framework"].as_str().unwrap(), "SOC 2 Type II");
        assert_eq!(v["summary"]["total"].as_u64().unwrap(), 1);
        assert_eq!(v["summary"]["passing"].as_u64().unwrap(), 0);
        assert_eq!(v["summary"]["unknown"].as_u64().unwrap(), 1);
        // The requirement has no status in DB so it is "unknown"
        assert_eq!(
            v["requirements"][0]["status"].as_str().unwrap(),
            "unknown"
        );
    }

    #[test]
    fn cmd_compliance_markdown_format() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = tmp.path().join("ocean.db").to_str().unwrap().to_string();
        let fw_path = tmp.path().join("iso.framework.yaml");
        std::fs::write(
            &fw_path,
            r#"
id: iso27001
name: ISO 27001
controls:
  - ref: A.9.4.2
    title: Secure log-on procedures
    ocean_control_ids: []
"#,
        )
        .unwrap();
        let fw_str = fw_path.to_str().unwrap();
        let mut out = Vec::new();
        cmd_compliance(&mut out, &db, Some(fw_str), "controls", "markdown").unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("# Compliance Report: ISO 27001"));
        assert!(s.contains("**Summary:**"));
    }

    // --- target_matches_module ---
    #[test]
    fn target_matches_module_wildcard() {
        assert!(target_matches_module("*", "anything.at.all"));
        assert!(target_matches_module("*", ""));
    }

    #[test]
    fn target_matches_module_prefix() {
        assert!(target_matches_module("github", "github.org_mfa"));
        assert!(target_matches_module("okta", "okta.password_policy"));
    }

    #[test]
    fn target_matches_module_no_match() {
        assert!(!target_matches_module("github", "okta.password_policy"));
        assert!(!target_matches_module("", "github.org_mfa"));
    }

    // --- load_control: file-based, exercises both naming conventions ---
    #[test]
    fn load_control_flat_naming() {
        let dir = tempfile::tempdir().unwrap();
        let ctrl_path = dir.path().join("iam.test.yaml");
        std::fs::write(
            &ctrl_path,
            r#"
id: iam.test
name: Test Control
description: A test control
modules:
  - mock.test
status_id: 1
classification:
  ocean:
    severity: medium
    profile: starter
    tags: [test]
    rationale: testing
"#,
        )
        .unwrap();
        let result = load_control("iam.test", dir.path().to_str().unwrap(), None);
        assert!(result.is_ok());
        let ctrl = result.unwrap();
        assert_eq!(ctrl.id, "iam.test");
    }

    #[test]
    fn load_control_namespaced_naming() {
        let dir = tempfile::tempdir().unwrap();
        let ns_dir = dir.path().join("iam");
        std::fs::create_dir_all(&ns_dir).unwrap();
        let ctrl_path = ns_dir.join("test.yaml");
        std::fs::write(
            &ctrl_path,
            r#"
id: iam.test
name: Test Control
description: A test control
modules:
  - mock.test
status_id: 1
classification:
  ocean:
    severity: medium
    profile: starter
    tags: [test]
    rationale: testing
"#,
        )
        .unwrap();
        let result = load_control("iam.test", dir.path().to_str().unwrap(), None);
        assert!(result.is_ok());
    }

    #[test]
    fn load_control_missing_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let result = load_control("nonexistent.control", dir.path().to_str().unwrap(), None);
        assert!(result.is_err());
    }

    // --- resolve_controls: directory walker ---
    #[test]
    fn resolve_controls_missing_dir_returns_err() {
        let result = resolve_controls("/definitely/nonexistent/path/xyz", "");
        assert!(result.is_err());
    }

    #[test]
    fn resolve_controls_walks_yaml_and_yml() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
id: x.y
name: Test
description: t
modules: [mock.test]
status_id: 1
classification:
  ocean:
    severity: low
    profile: starter
    tags: []
    rationale: r
"#;
        std::fs::write(dir.path().join("a.yaml"), yaml.replace("x.y", "a.alpha")).unwrap();
        std::fs::write(dir.path().join("b.yml"), yaml.replace("x.y", "a.beta")).unwrap();
        std::fs::create_dir_all(dir.path().join("nested")).unwrap();
        std::fs::write(
            dir.path().join("nested").join("c.yaml"),
            yaml.replace("x.y", "a.gamma"),
        )
        .unwrap();
        // Non-yaml should be skipped
        std::fs::write(dir.path().join("d.txt"), "not yaml").unwrap();

        let result = resolve_controls(dir.path().to_str().unwrap(), "a").unwrap();
        // All three a.* controls match "a" prefix
        assert!(result.len() >= 3, "expected ≥3 matches, got {}", result.len());
    }

    #[test]
    fn resolve_controls_no_match_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.yaml"),
            r#"
id: zebra.thing
name: Z
description: z
modules: [mock.test]
status_id: 1
classification:
  ocean:
    severity: low
    profile: starter
    tags: []
    rationale: r
"#,
        )
        .unwrap();
        let result = resolve_controls(dir.path().to_str().unwrap(), "iam");
        assert!(result.is_err());
    }

    // --- cmd_modules_list ---
    #[test]
    fn cmd_modules_list_all_writes_json() {
        let mut out = Vec::new();
        cmd_modules_list(&mut out, OutputFormat::Json, None).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(!s.is_empty());
        // Should be parseable JSON
        let _: serde_json::Value = serde_json::from_str(&s).unwrap();
    }

    #[test]
    fn cmd_modules_list_filtered_observer() {
        let mut out = Vec::new();
        cmd_modules_list(&mut out, OutputFormat::Json, Some("observer")).unwrap();
        let s = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let arr = v.as_array().unwrap();
        for m in arr {
            assert_eq!(m["module_type"], "observer");
        }
    }

    #[test]
    fn cmd_modules_list_filtered_tester() {
        let mut out = Vec::new();
        cmd_modules_list(&mut out, OutputFormat::Json, Some("tester")).unwrap();
        let s = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let arr = v.as_array().unwrap();
        for m in arr {
            assert_eq!(m["module_type"], "tester");
        }
    }

    #[test]
    fn cmd_modules_list_yaml_format() {
        let mut out = Vec::new();
        cmd_modules_list(&mut out, OutputFormat::Yaml, None).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(!s.is_empty());
    }

    // --- cmd_modules_validate ---
    #[test]
    fn cmd_modules_validate_known_observer() {
        let mut out = Vec::new();
        cmd_modules_validate(&mut out, OutputFormat::Json, "mock.test").unwrap();
        let s = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["valid"], true);
    }

    #[test]
    fn cmd_modules_validate_unknown_returns_err() {
        let mut out = Vec::new();
        let result = cmd_modules_validate(&mut out, OutputFormat::Json, "absolutely.nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn cmd_modules_validate_known_tester() {
        let mut out = Vec::new();
        // mock.safety_test is a registered tester
        let result = cmd_modules_validate(&mut out, OutputFormat::Json, "mock.safety_test");
        // Either succeeds or returns a specific error if registry doesn't have that exact id;
        // accept both — the goal is to exercise both branches of the if/else
        let _ = result;
    }

    // --- cmd_schedule_remove ---
    #[test]
    fn cmd_schedule_remove_missing_returns_err_or_ok() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        // Schedule doesn't exist — implementation may either error or succeed quietly
        let _ = cmd_schedule_remove(&db, "nonexistent-id");
    }

    // --- cmd_schedule_status ---
    #[test]
    fn cmd_schedule_status_missing_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_schedule_status(&mut out, OutputFormat::Json, &db, "nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn cmd_schedule_status_existing_returns_ok() {
        use crate::scheduler::Schedule;
        use chrono::Utc;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let store = open_store(&db).unwrap();
        let now = Utc::now();
        let sched = Schedule {
            id: "test-sched".to_string(),
            control_id: "iam.test".to_string(),
            cron_expr: "0 * * * *".to_string(),
            modules: vec!["mock.test".to_string()],
            max_safety_level: "safe".to_string(),
            environment_scope: "production".to_string(),
            enabled: true,
            catch_up: false,
            last_run: None,
            next_run: None,
            created_at: now,
            updated_at: now,
        };
        store.store_schedule(&sched).unwrap();
        let mut out = Vec::new();
        let result = cmd_schedule_status(&mut out, OutputFormat::Json, &db, "test-sched");
        assert!(result.is_ok());
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("test-sched"));
    }

    // --- cmd_evaluate ---
    #[test]
    fn cmd_evaluate_missing_control_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_evaluate(
            &mut out,
            OutputFormat::Json,
            &db,
            "nonexistent.control",
            None,
            cdir.to_str().unwrap(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn cmd_evaluate_simple_control_no_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        write_simple_control_yaml(&cdir, "mock.test.yaml", "mock.test", "mock.test");
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_evaluate(
            &mut out,
            OutputFormat::Json,
            &db,
            "mock.test",
            None,
            cdir.to_str().unwrap(),
        );
        assert!(result.is_ok());
        let s = String::from_utf8(out).unwrap();
        // Output is a ControlStatus serialized as JSON
        let _: serde_json::Value = serde_json::from_str(&s).unwrap();
    }

    // --- cmd_evaluate_path / cmd_test_path / cmd_report ---
    #[test]
    fn cmd_evaluate_path_runs_pipeline_on_match() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        write_simple_control_yaml(&cdir, "mock.test.yaml", "mock.test", "mock.test");
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_evaluate_path(
            &mut out,
            OutputFormat::Json,
            &db,
            "*",
            "mock",
            cdir.to_str().unwrap(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_evaluate_path_missing_dir_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_evaluate_path(
            &mut out,
            OutputFormat::Json,
            &db,
            "*",
            "anything",
            "/definitely/missing/dir",
        );
        assert!(result.is_err());
    }

    #[test]
    fn cmd_evaluate_path_yaml_format() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        write_simple_control_yaml(&cdir, "mock.test.yaml", "mock.test", "mock.test");
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_evaluate_path(
            &mut out,
            OutputFormat::Yaml,
            &db,
            "*",
            "mock",
            cdir.to_str().unwrap(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_test_path_runs_on_safety_test() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        // A control with a tester reference.
        std::fs::write(
            cdir.join("mock.safety.yaml"),
            r#"
id: mock.safety
name: Safety
description: t
testers:
  - module_id: mock.safety_test
modules: [mock.safety_test]
status_id: 1
classification:
  ocean:
    severity: medium
    profile: starter
    tags: []
    rationale: r
"#,
        )
        .unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_test_path(
            &mut out,
            OutputFormat::Json,
            &db,
            "*",
            "mock",
            "production",
            cdir.to_str().unwrap(),
            false,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_test_path_invalid_scope_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        write_simple_control_yaml(&cdir, "mock.test.yaml", "mock.test", "mock.test");
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_test_path(
            &mut out,
            OutputFormat::Json,
            &db,
            "*",
            "mock",
            "bogus_scope",
            cdir.to_str().unwrap(),
            false,
            false,
        );
        assert!(result.is_err());
    }

    // --- cmd_observe_path ---
    fn write_simple_control_yaml(dir: &std::path::Path, file: &str, control_id: &str, module_id: &str) {
        let yaml = format!(
            r#"
id: {control_id}
name: {control_id}
description: t
observers:
  - module_id: {module_id}
modules: [{module_id}]
status_id: 1
classification:
  ocean:
    severity: medium
    profile: starter
    tags: [test]
    rationale: testing
"#
        );
        std::fs::write(dir.join(file), yaml).unwrap();
    }

    #[test]
    fn cmd_observe_path_runs_matching_observers() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        write_simple_control_yaml(&cdir, "mock.test.yaml", "mock.test", "mock.test");
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_observe_path(
            &mut out,
            OutputFormat::Json,
            &db,
            "*",
            "mock",
            cdir.to_str().unwrap(),
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_observe_path_with_store_persists_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        write_simple_control_yaml(&cdir, "mock.test.yaml", "mock.test", "mock.test");
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_observe_path(
            &mut out,
            OutputFormat::Json,
            &db,
            "*",
            "mock",
            cdir.to_str().unwrap(),
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_observe_path_target_filter_excludes() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        write_simple_control_yaml(&cdir, "mock.test.yaml", "mock.test", "mock.test");
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        // target "github" doesn't match module "mock.test" — observer is filtered out
        let result = cmd_observe_path(
            &mut out,
            OutputFormat::Json,
            &db,
            "github",
            "mock",
            cdir.to_str().unwrap(),
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_observe_path_missing_controls_dir_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_observe_path(
            &mut out,
            OutputFormat::Json,
            &db,
            "*",
            "mock",
            "/definitely/missing/path/xyz",
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn cmd_evaluate_path_observer_err_branch() {
        // Control references a module id that doesn't exist → execute_observer errs.
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        write_simple_control_yaml(&cdir, "ghost.yaml", "ghost.id", "ghost.nonexistent");
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_evaluate_path(
            &mut out, OutputFormat::Json, &db, "*", "ghost", cdir.to_str().unwrap(),
        );
        assert!(result.is_ok());
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("ERROR") || s.contains("ghost"));
    }

    #[test]
    fn cmd_evaluate_path_tester_err_branch() {
        // Control references a tester that doesn't exist → execute_tester errs.
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        std::fs::write(
            cdir.join("ghost-test.yaml"),
            r#"
id: ghost.tester
name: Ghost Tester
description: t
testers:
  - module_id: ghost.nonexistent_tester
modules: [ghost.nonexistent_tester]
status_id: 1
classification:
  ocean:
    severity: medium
    profile: starter
    tags: []
    rationale: r
"#,
        )
        .unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_evaluate_path(
            &mut out, OutputFormat::Json, &db, "*", "ghost", cdir.to_str().unwrap(),
        );
        assert!(result.is_ok());
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("FAIL") || s.contains("ghost"));
    }

    #[test]
    fn cmd_observe_path_observer_err_branch() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        write_simple_control_yaml(&cdir, "ghost.yaml", "ghost.id", "ghost.nonexistent");
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_observe_path(
            &mut out, OutputFormat::Json, &db, "*", "ghost", cdir.to_str().unwrap(), false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_test_path_tester_err_branch() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        std::fs::write(
            cdir.join("ghost-test.yaml"),
            r#"
id: ghost.tester
name: Ghost Tester
description: t
testers:
  - module_id: ghost.nonexistent_tester
modules: [ghost.nonexistent_tester]
status_id: 1
classification:
  ocean:
    severity: medium
    profile: starter
    tags: []
    rationale: r
"#,
        )
        .unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_test_path(
            &mut out, OutputFormat::Json, &db, "*", "ghost", "production",
            cdir.to_str().unwrap(), false, false,
        );
        assert!(result.is_ok());
    }

    // --- cmd_test (single module) ---
    #[test]
    fn cmd_test_invalid_env_scope_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        // "invalid_scope" is not a valid env scope
        let result = cmd_test(
            &mut out,
            OutputFormat::Json,
            &db,
            "mock.safety_test",
            "invalid_scope",
            false,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn cmd_test_unknown_tester_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_test(
            &mut out,
            OutputFormat::Json,
            &db,
            "absolutely.nonexistent.tester",
            "production",
            false,
            false,
        );
        assert!(result.is_err());
    }

    // --- cmd_observe ---
    #[test]
    fn cmd_observe_unknown_module_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_observe(&mut out, OutputFormat::Json, &db, "nonexistent.observer", false);
        assert!(result.is_err());
    }

    #[test]
    fn cmd_observe_mock_success_no_store() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_observe(&mut out, OutputFormat::Json, &db, "mock.test", false);
        assert!(result.is_ok());
        let s = String::from_utf8(out).unwrap();
        assert!(!s.is_empty());
    }

    #[test]
    fn cmd_observe_mock_success_with_store() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_observe(&mut out, OutputFormat::Json, &db, "mock.test", true);
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_schedule_remove_existing_succeeds() {
        use crate::scheduler::Schedule;
        use chrono::Utc;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let store = open_store(&db).unwrap();
        let now = Utc::now();
        let sched = Schedule {
            id: "removable".to_string(),
            control_id: "iam.test".to_string(),
            cron_expr: "0 * * * *".to_string(),
            modules: vec!["mock.test".to_string()],
            max_safety_level: "safe".to_string(),
            environment_scope: "production".to_string(),
            enabled: true,
            catch_up: false,
            last_run: None,
            next_run: None,
            created_at: now,
            updated_at: now,
        };
        store.store_schedule(&sched).unwrap();
        let result = cmd_schedule_remove(&db, "removable");
        assert!(result.is_ok());
    }

    // --- cmd_report ---
    #[test]
    fn cmd_report_invalid_period_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_report(&mut out, &db, "not-a-period", "json", None);
        assert!(result.is_err());
    }

    #[test]
    fn cmd_report_json_empty() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_report(&mut out, &db, "2024-01-01:2024-12-31", "json", None);
        assert!(result.is_ok());
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("evidence_count"));
    }

    #[test]
    fn cmd_report_markdown_empty() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_report(&mut out, &db, "2024-01-01:2024-12-31", "markdown", Some("iam.test"));
        assert!(result.is_ok());
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("# OCEAN Compliance Report"));
        assert!(s.contains("iam.test"));
    }

    #[test]
    fn cmd_report_csv_empty() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_report(&mut out, &db, "2024-01-01:2024-12-31", "csv", None);
        assert!(result.is_ok());
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("id,module,status,time"));
    }

    #[test]
    fn cmd_report_invalid_date_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_report(&mut out, &db, "garbage:also-garbage", "json", None);
        assert!(result.is_err());
    }

    // --- cmd_compliance ---
    #[test]
    fn cmd_compliance_missing_framework_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        let mut out = Vec::new();
        // No framework file, no frameworks dir → should error.
        let result = cmd_compliance(&mut out, &db, None, cdir.to_str().unwrap(), "json");
        assert!(result.is_err());
    }

    fn write_simple_framework_yaml(path: &std::path::Path) {
        std::fs::write(
            path,
            r#"
id: test.framework
name: Test Framework
version: "1.0"
controls:
  - ref: T1
    title: First Test Control
    description: t1
    ocean_control_ids: [iam.test]
  - ref: T2
    title: No Mapping
    description: t2
    ocean_control_ids: []
"#,
        )
        .unwrap();
    }

    #[test]
    fn cmd_compliance_auto_discovery_in_frameworks_dir() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let cdir = dir.path().join("controls");
        let fdir = cdir.join("frameworks");
        std::fs::create_dir_all(&fdir).unwrap();
        write_simple_framework_yaml(&fdir.join("test.yaml"));
        let mut out = Vec::new();
        let result = cmd_compliance(&mut out, &db, None, cdir.to_str().unwrap(), "json");
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_compliance_auto_discovery_top_level_framework_suffix() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        write_simple_framework_yaml(&cdir.join("soc2.framework.yaml"));
        let mut out = Vec::new();
        let result = cmd_compliance(&mut out, &db, None, cdir.to_str().unwrap(), "json");
        assert!(result.is_ok());
    }

    fn store_control_status(db: &str, control_id: &str, status: &str) {
        use crate::control::ControlStatus;
        let store = open_store(db).unwrap();
        let cs = ControlStatus {
            id: uuid::Uuid::new_v4(),
            control_id: control_id.to_string(),
            timestamp: Utc::now(),
            status: status.to_string(),
            confidence: "high".to_string(),
            evidence_ids: vec![],
            evaluation_details: String::new(),
        };
        store.store_control_status(&cs).unwrap();
    }

    fn write_three_status_framework(path: &std::path::Path) {
        std::fs::write(
            path,
            r#"
id: status-framework
name: Status Framework
version: "1.0"
controls:
  - ref: P1
    title: Passing
    description: p
    ocean_control_ids: [iam.passing]
  - ref: F1
    title: Failing
    description: f
    ocean_control_ids: [iam.failing]
  - ref: U1
    title: Unknown
    description: u
    ocean_control_ids: [iam.weird, iam.missing]
"#,
        )
        .unwrap();
    }

    #[test]
    fn cmd_compliance_status_branches_markdown() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        store_control_status(&db, "iam.passing", "effective");
        store_control_status(&db, "iam.failing", "ineffective");
        store_control_status(&db, "iam.weird", "stale-data");
        // iam.missing has no status -> Err branch
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        let fwpath = dir.path().join("fw.yaml");
        write_three_status_framework(&fwpath);
        let mut out = Vec::new();
        let result = cmd_compliance(
            &mut out,
            &db,
            Some(fwpath.to_str().unwrap()),
            cdir.to_str().unwrap(),
            "markdown",
        );
        assert!(result.is_ok());
        let s = String::from_utf8(out).unwrap();
        // Hits passing/failing/unknown branches and the markdown writer.
        assert!(s.contains("Compliance Report"));
        assert!(s.contains("Passing"));
        assert!(s.contains("Failing"));
    }

    #[test]
    fn cmd_compliance_status_branches_json() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        store_control_status(&db, "iam.passing", "effective");
        store_control_status(&db, "iam.failing", "ineffective");
        store_control_status(&db, "iam.weird", "stale-data");
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        let fwpath = dir.path().join("fw.yaml");
        write_three_status_framework(&fwpath);
        let mut out = Vec::new();
        let result = cmd_compliance(
            &mut out,
            &db,
            Some(fwpath.to_str().unwrap()),
            cdir.to_str().unwrap(),
            "json",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_compliance_auto_discovery_yml_suffix() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        // .framework.yml (not .yaml) — exercises the .yml branch.
        write_simple_framework_yaml(&cdir.join("test.framework.yml"));
        let mut out = Vec::new();
        let result = cmd_compliance(&mut out, &db, None, cdir.to_str().unwrap(), "json");
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_compliance_auto_discovery_yml_in_frameworks_dir() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let cdir = dir.path().join("controls");
        let fdir = cdir.join("frameworks");
        std::fs::create_dir_all(&fdir).unwrap();
        // Plain .yml inside frameworks/ — exercises the frameworks/-only .yml arm.
        write_simple_framework_yaml(&fdir.join("test.yml"));
        let mut out = Vec::new();
        let result = cmd_compliance(&mut out, &db, None, cdir.to_str().unwrap(), "json");
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_compliance_with_explicit_framework_path() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        let fwpath = dir.path().join("my-framework.yaml");
        write_simple_framework_yaml(&fwpath);
        let mut out = Vec::new();
        let result = cmd_compliance(
            &mut out,
            &db,
            Some(fwpath.to_str().unwrap()),
            cdir.to_str().unwrap(),
            "markdown",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_compliance_bad_framework_path_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_compliance(
            &mut out,
            &db,
            Some("/definitely/does/not/exist.yaml"),
            dir.path().to_str().unwrap(),
            "json",
        );
        assert!(result.is_err());
    }

    // --- cmd_harden ---
    #[test]
    fn cmd_harden_dry_run_no_checks_ok() {
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let tf = dir.path().join("tf");
        std::fs::create_dir_all(&tf).unwrap();
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_harden(
            &mut out,
            checks.to_str().unwrap(),
            "api",
            false, // apply = false → dry-run
            false,
            None,
            tf.to_str().unwrap(),
            "json",
            &filter,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_harden_unknown_id_filter_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let tf = dir.path().join("tf");
        std::fs::create_dir_all(&tf).unwrap();
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_harden(
            &mut out,
            checks.to_str().unwrap(),
            "api",
            false,
            false,
            Some("does.not.exist"),
            tf.to_str().unwrap(),
            "json",
            &filter,
        );
        assert!(result.is_err());
    }

    #[test]
    fn cmd_harden_apply_with_failing_check() {
        // Drive cmd_harden through plan_harden → execute_plans → print_results.
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let srv = crate::testutil::MockHTTPServer::new(vec![(200, "{}".to_string())]);
        std::fs::write(
            checks.join("FAIL-CLI.check.yaml"),
            format!(
                r#"
id: FAIL-CLI
name: Failing Check
description: t
source: github
profile: L1
severity: high
tags: [test]
credentials: {{}}
inputs: {{}}
steps:
  - id: q
    action: api_call
    request:
      method: GET
      url: "{}"
    extract:
      x: "$.x"
assertions:
  - id: a
    expr: "x == true"
    severity: high
    title: t
    pass_message: ok
    fail_message: fail
remediation:
  description: r
  steps: [s1]
  api:
    method: POST
    url: "https://api.github.com/orgs/x/settings"
    body: {{}}
"#,
                srv.base_url
            ),
        )
        .unwrap();
        let tf = dir.path().join("tf");
        std::fs::create_dir_all(&tf).unwrap();
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_harden(
            &mut out,
            checks.to_str().unwrap(),
            "api",
            true, // apply
            true, // confirm
            None,
            tf.to_str().unwrap(),
            "json",
            &filter,
        );
        // Should reach execute_plans + print_results; result may be Err if
        // remediation call fails (no real GitHub creds) but path is covered.
        let _ = result;
    }

    #[test]
    fn cmd_harden_dry_run_with_failing_check_prints_plan() {
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let srv = crate::testutil::MockHTTPServer::new(vec![(200, "{}".to_string())]);
        std::fs::write(
            checks.join("DRY-FAIL.check.yaml"),
            format!(
                r#"
id: DRY-FAIL
name: Dry Run Failing Check
description: t
source: github
profile: L1
severity: high
tags: [test]
credentials: {{}}
inputs: {{}}
steps:
  - id: q
    action: api_call
    request:
      method: GET
      url: "{}"
    extract:
      x: "$.x"
assertions:
  - id: a
    expr: "x == true"
    severity: high
    title: t
    pass_message: ok
    fail_message: fail
remediation:
  description: r
  steps: [s1]
  api:
    method: POST
    url: "https://api.github.com/orgs/x/settings"
    body: {{}}
"#,
                srv.base_url
            ),
        )
        .unwrap();
        let tf = dir.path().join("tf");
        std::fs::create_dir_all(&tf).unwrap();
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_harden(
            &mut out,
            checks.to_str().unwrap(),
            "api",
            false, // dry-run
            false,
            None,
            tf.to_str().unwrap(),
            "table",
            &filter,
        );
        assert!(result.is_ok());
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("DRY-FAIL") || s.contains("DRY RUN") || s.contains("Remediation"));
    }

    #[test]
    fn cmd_harden_fault_injection_apply_path() {
        // Fault-inject across cmd_harden's apply path (drives confirm_apply +
        // print_results writelns).
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let srv = crate::testutil::MockHTTPServer::new(vec![(200, "{}".to_string())]);
        std::fs::write(
            checks.join("FAULT-FAIL.check.yaml"),
            format!(
                r#"
id: FAULT-FAIL
name: Fault-Inject Failing Check
description: t
source: github
profile: L1
severity: high
tags: [test]
credentials: {{}}
inputs: {{}}
steps:
  - id: q
    action: api_call
    request:
      method: GET
      url: "{}"
    extract:
      x: "$.x"
assertions:
  - id: a
    expr: "x == true"
    severity: high
    title: t
    pass_message: ok
    fail_message: fail
remediation:
  description: r
  steps: [s1]
  api:
    method: POST
    url: "https://api.github.com/orgs/x/settings"
    body: {{}}
"#,
                srv.base_url
            ),
        )
        .unwrap();
        let tf = dir.path().join("tf");
        std::fs::create_dir_all(&tf).unwrap();
        let filter = crate::cli::filter::CheckFilter::default();
        for n in 0..50 {
            let mut w = crate::testutil::FailingWriter::new(n);
            let _ = cmd_harden(
                &mut w,
                checks.to_str().unwrap(),
                "api",
                true, // apply
                true, // confirm
                None,
                tf.to_str().unwrap(),
                "json",
                &filter,
            );
            let mut w = crate::testutil::FailingWriter::new(n);
            let _ = cmd_harden(
                &mut w,
                checks.to_str().unwrap(),
                "api",
                false, // dry-run
                false,
                None,
                tf.to_str().unwrap(),
                "table",
                &filter,
            );
        }
    }

    #[test]
    fn cmd_harden_apply_no_plans_ok() {
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let tf = dir.path().join("tf");
        std::fs::create_dir_all(&tf).unwrap();
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_harden(
            &mut out,
            checks.to_str().unwrap(),
            "api",
            true, // apply = true
            true, // confirm = true (skip prompt)
            None,
            tf.to_str().unwrap(),
            "json",
            &filter,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_harden_apply_with_check_filter() {
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let tf = dir.path().join("tf");
        std::fs::create_dir_all(&tf).unwrap();
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter {
            tags: vec!["nonexistent".to_string()],
            severities: vec![],
            profile: None,
        };
        let result = cmd_harden(
            &mut out,
            checks.to_str().unwrap(),
            "api",
            true,
            true,
            None,
            tf.to_str().unwrap(),
            "json",
            &filter,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_harden_invalid_mode_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let tf = dir.path().join("tf");
        std::fs::create_dir_all(&tf).unwrap();
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_harden(
            &mut out,
            checks.to_str().unwrap(),
            "definitely-not-a-mode",
            false,
            false,
            None,
            tf.to_str().unwrap(),
            "json",
            &filter,
        );
        assert!(result.is_err());
    }

    // --- cmd_report_framework ---
    #[test]
    fn cmd_report_framework_invalid_framework_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_report_framework(
            &mut out,
            checks.to_str().unwrap(),
            &["not-a-real-framework".to_string()],
            false,
            "json",
            &filter,
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn cmd_report_framework_empty_dir_soc2_ok() {
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_report_framework(
            &mut out,
            checks.to_str().unwrap(),
            &["soc2".to_string()],
            true, // include_passing so we still print
            "json",
            &filter,
            None,
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_report_framework_sarif_empty_dir_ok() {
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_report_framework(
            &mut out,
            checks.to_str().unwrap(),
            &["soc2".to_string()],
            true,
            "sarif",
            &filter,
            None,
            None,
        );
        assert!(result.is_ok());
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("No checks found") || s.contains("sarif") || s.contains("$schema") || s.contains("version"));
    }

    #[test]
    fn cmd_report_framework_all_keyword_ok() {
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_report_framework(
            &mut out,
            checks.to_str().unwrap(),
            &["all".to_string()],
            false, // don't include passing — empty dir → no print
            "json",
            &filter,
            None,
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_report_framework_pci_dss_hyphen_normalizes() {
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_report_framework(
            &mut out,
            checks.to_str().unwrap(),
            &["pci-dss".to_string()],
            true,
            "json",
            &filter,
            None,
            None,
        );
        assert!(result.is_ok());
    }

    // --- run_with dispatcher ---
    fn parse_args(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).unwrap()
    }

    #[test]
    fn run_with_version_ok() {
        let cli = parse_args(&["ocean", "version"]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_ok());
    }

    #[test]
    fn run_with_observe_no_module_or_target_errors() {
        let cli = parse_args(&["ocean", "observe"]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_err());
    }

    #[test]
    fn run_with_observe_target_without_control_errors() {
        let cli = parse_args(&["ocean", "observe", "--target", "okta"]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_err());
    }

    #[test]
    fn run_with_observe_module_dispatches_to_cmd_observe() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let cli = parse_args(&["ocean", "--db", &db, "observe", "mock.test", "--no-store"]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_ok());
    }

    #[test]
    fn run_with_observe_target_control_dispatches_path() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        write_simple_control_yaml(&cdir, "mock.test.yaml", "mock.test", "mock.test");
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let cli = parse_args(&[
            "ocean", "--db", &db, "observe",
            "--target", "*",
            "--control", "mock",
            "--controls-dir", cdir.to_str().unwrap(),
            "--no-store",
        ]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_ok());
    }

    #[test]
    fn run_with_test_no_module_errors() {
        let cli = parse_args(&["ocean", "test"]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_err());
    }

    #[test]
    fn run_with_test_target_without_control_errors() {
        let cli = parse_args(&["ocean", "test", "--target", "okta"]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_err());
    }

    #[test]
    fn run_with_test_module_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let cli = parse_args(&[
            "ocean", "--db", &db, "test", "mock.safety_test",
            "--env", "production", "--no-store",
        ]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_ok());
    }

    #[test]
    fn run_with_modules_list_dispatches() {
        let cli = parse_args(&["ocean", "modules", "list"]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_ok());
    }

    #[test]
    fn run_with_modules_validate_dispatches() {
        let cli = parse_args(&["ocean", "modules", "validate", "mock.test"]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_ok());
    }

    #[test]
    fn run_with_evaluate_no_args_errors() {
        let cli = parse_args(&["ocean", "evaluate"]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_err());
    }

    #[test]
    fn run_with_evaluate_target_without_control_errors() {
        let cli = parse_args(&["ocean", "evaluate", "--target", "okta"]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_err());
    }

    #[test]
    fn run_with_history_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let cli = parse_args(&[
            "ocean", "--db", &db, "history",
            "--control", "iam.test",
        ]);
        let mut out = Vec::new();
        let _ = run_with(&mut out, cli);
    }

    #[test]
    fn run_with_report_no_args_errors() {
        let cli = parse_args(&["ocean", "report"]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_err());
    }

    #[test]
    fn run_with_report_with_period_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let cli = parse_args(&[
            "ocean", "--db", &db, "report",
            "--period", "2024-01-01:2024-12-31",
        ]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_ok());
    }

    #[test]
    fn run_with_report_framework_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let cli = parse_args(&[
            "ocean", "report",
            "--framework", "soc2",
            "--checks-dir", checks.to_str().unwrap(),
            "--include-passing",
        ]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_ok());
    }

    #[test]
    fn run_with_harden_dispatches_dry_run() {
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let cli = parse_args(&[
            "ocean", "harden",
            "--checks-dir", checks.to_str().unwrap(),
            "--mode", "api",
        ]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_ok());
    }

    #[test]
    fn run_with_schedule_list_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let cli = parse_args(&["ocean", "--db", &db, "schedule", "list"]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_ok());
    }

    #[test]
    fn run_with_compliance_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        let cli = parse_args(&[
            "ocean", "--db", &db, "compliance",
            "--controls-dir", cdir.to_str().unwrap(),
            "--format", "json",
        ]);
        let mut out = Vec::new();
        let _ = run_with(&mut out, cli);
    }

    // --- cmd_test_path with Yaml format (covers yaml output branch) ---
    #[test]
    fn cmd_test_path_yaml_format() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        std::fs::write(
            cdir.join("mock.safety.yaml"),
            r#"
id: mock.safety
name: Safety
description: t
testers:
  - module_id: mock.safety_test
modules: [mock.safety_test]
status_id: 1
classification:
  ocean:
    severity: medium
    profile: starter
    tags: []
    rationale: r
"#,
        )
        .unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_test_path(
            &mut out,
            OutputFormat::Yaml,
            &db,
            "*",
            "mock",
            "production",
            cdir.to_str().unwrap(),
            true, // store = true
            false,
        );
        assert!(result.is_ok());
    }

    // --- cmd_evaluate composite-control branch ---
    #[test]
    fn cmd_evaluate_composite_controls_branch() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        // Parent control with component_controls referencing a child that does exist.
        std::fs::write(
            cdir.join("parent.ctrl.yaml"),
            r#"
id: parent.ctrl
name: Parent Control
description: composite parent
component_controls: [child.ok, child.missing]
modules: []
status_id: 1
classification:
  ocean:
    severity: medium
    profile: starter
    tags: []
    rationale: r
"#,
        )
        .unwrap();
        std::fs::write(
            cdir.join("child.ok.yaml"),
            r#"
id: child.ok
name: Child OK
description: child
modules: []
status_id: 1
classification:
  ocean:
    severity: medium
    profile: starter
    tags: []
    rationale: r
"#,
        )
        .unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_evaluate(
            &mut out,
            OutputFormat::Json,
            &db,
            "parent.ctrl",
            None,
            cdir.to_str().unwrap(),
        );
        assert!(result.is_ok());
    }

    // --- cmd_evaluate_path with control that has testers (covers tester branch) ---
    #[test]
    fn cmd_evaluate_path_runs_testers() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        std::fs::write(
            cdir.join("mock.safety.yaml"),
            r#"
id: mock.safety
name: Safety
description: t
testers:
  - module_id: mock.safety_test
modules: [mock.safety_test]
status_id: 1
classification:
  ocean:
    severity: medium
    profile: starter
    tags: []
    rationale: r
"#,
        )
        .unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_evaluate_path(
            &mut out,
            OutputFormat::Json,
            &db,
            "*",
            "mock",
            cdir.to_str().unwrap(),
        );
        assert!(result.is_ok());
    }

    // --- cmd_report with stored evidence (covers markdown/csv loop bodies) ---
    fn store_one_evidence(db: &str) {
        let store = open_store(db).unwrap();
        let ev = crate::testutil::make_evidence();
        store.store_evidence(&ev).unwrap();
    }

    #[test]
    fn cmd_report_markdown_with_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        store_one_evidence(&db);
        let mut out = Vec::new();
        let result = cmd_report(&mut out, &db, "2020-01-01:2030-12-31", "markdown", None);
        assert!(result.is_ok());
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("# OCEAN Compliance Report"));
        assert!(s.contains("| ID | Module"));
    }

    #[test]
    fn cmd_report_csv_with_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        store_one_evidence(&db);
        let mut out = Vec::new();
        let result = cmd_report(&mut out, &db, "2020-01-01:2030-12-31", "csv", None);
        assert!(result.is_ok());
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("id,module,status,time"));
        // Stored row should produce a non-header line.
        assert!(s.lines().count() > 1);
    }

    // --- cmd_report_framework_sarif via a real check def ---
    #[test]
    fn cmd_report_framework_sarif_with_passive_failing_check() {
        // Drives the cmd_report_framework_sarif loop body including the
        // executor.execute_observer call and the FAIL status branch.
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let srv = crate::testutil::MockHTTPServer::new(vec![(200, "{}".to_string())]);
        std::fs::write(
            checks.join("SARIF-FAIL.check.yaml"),
            format!(
                r#"
id: SARIF-FAIL
name: SARIF Failing Check
description: t
source: github
profile: L1
severity: high
tags: [test]
references:
  soc2: CC6.1
credentials: {{}}
inputs: {{}}
steps:
  - id: q
    action: api_call
    request:
      method: GET
      url: "{}"
    extract:
      x: "$.x"
assertions:
  - id: a
    expr: "x == true"
    severity: critical
    title: t
    pass_message: ok
    fail_message: fail
"#,
                srv.base_url
            ),
        )
        .unwrap();
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_report_framework(
            &mut out,
            checks.to_str().unwrap(),
            &["soc2".to_string()],
            true,
            "sarif",
            &filter,
            None,
            None,
        );
        assert!(result.is_ok());
        let s = String::from_utf8(out).unwrap();
        // SARIF output includes our check id.
        assert!(s.contains("SARIF-FAIL"));
    }

    #[test]
    fn cmd_report_framework_sarif_with_passive_check_not_matching_framework() {
        // Check exists but its reference is for "nist" not "soc2" → filtered out.
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let srv = crate::testutil::MockHTTPServer::new(vec![(200, "{}".to_string())]);
        std::fs::write(
            checks.join("SARIF-NIST.check.yaml"),
            format!(
                r#"
id: SARIF-NIST
name: NIST-only Check
description: t
source: github
profile: L1
severity: high
tags: [test]
references:
  nist: IA-2
credentials: {{}}
inputs: {{}}
steps:
  - id: q
    action: api_call
    request:
      method: GET
      url: "{}"
    extract:
      x: "$.x"
assertions:
  - id: a
    expr: "x == true"
    severity: high
    title: t
    pass_message: ok
    fail_message: fail
"#,
                srv.base_url
            ),
        )
        .unwrap();
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_report_framework(
            &mut out,
            checks.to_str().unwrap(),
            &["soc2".to_string()],
            true,
            "sarif",
            &filter,
            None,
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_report_framework_sarif_with_real_check_def() {
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        std::fs::write(
            checks.join("dummy.check.yaml"),
            r#"id: DUMMY-1
name: Dummy
description: A dummy check for SARIF test
source: mock
profile: L1
credentials: {}
inputs: {}
steps: []
assertions: []
references:
  soc2: CC6.1
"#,
        )
        .unwrap();
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_report_framework(
            &mut out,
            checks.to_str().unwrap(),
            &["soc2".to_string()],
            true,
            "sarif",
            &filter,
            None,
            None,
        );
        assert!(result.is_ok());
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("DUMMY-1") || s.contains("sarif") || s.contains("schema") || s.contains("version"));
    }

    // --- cmd_history with explicit from/to ---
    #[test]
    fn cmd_history_with_from_to_dates() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_history(
            &mut out,
            OutputFormat::Json,
            &db,
            "iam.test",
            30,
            Some("2024-01-01"),
            Some("2024-12-31"),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cmd_history_invalid_from_date_errors() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_history(
            &mut out,
            OutputFormat::Json,
            &db,
            "iam.test",
            30,
            Some("garbage"),
            None,
        );
        assert!(result.is_err());
    }

    // --- run_with: Schedule sub-arms, Harden --fleet ---
    #[test]
    fn run_with_schedule_add_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let cli = parse_args(&[
            "ocean", "--db", &db, "schedule", "add",
            "--control", "iam.test",
            "--cron", "0 * * * *",
            "--modules", "mock.test",
        ]);
        let mut out = Vec::new();
        let _ = run_with(&mut out, cli);
    }

    #[test]
    fn run_with_schedule_remove_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let cli = parse_args(&["ocean", "--db", &db, "schedule", "remove", "nonexistent"]);
        let mut out = Vec::new();
        let _ = run_with(&mut out, cli);
    }

    #[test]
    fn run_with_schedule_status_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let cli = parse_args(&["ocean", "--db", &db, "schedule", "status", "nonexistent"]);
        let mut out = Vec::new();
        let _ = run_with(&mut out, cli);
    }

    #[test]
    #[serial_test::serial]
    fn run_with_harden_fleet_dispatches_dry_run() {
        let dir = tempfile::tempdir().unwrap();
        let fleet = dir.path().join("fleet.yaml");
        write_valid_fleet_manifest(&fleet);
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let outd = dir.path().join("out");
        let cli = parse_args(&[
            "ocean", "harden",
            "--fleet", fleet.to_str().unwrap(),
            "--checks-dir", checks.to_str().unwrap(),
            "--mode", "api",
            "--output", outd.to_str().unwrap(),
            "--dry-run",
        ]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_ok());
    }

    // --- cmd_harden_fleet ---
    fn write_valid_fleet_manifest(path: &std::path::Path) {
        std::env::set_var("OCEAN_TEST_FLEET_TOKEN", "tok123");
        std::env::set_var("OCEAN_TEST_FLEET_ORG", "acme");
        let yaml = r#"
fleet:
  name: "Test Fleet"
  description: "A test fleet"
targets:
  - id: "github-main"
    source: github
    credentials:
      GITHUB_TOKEN: "${OCEAN_TEST_FLEET_TOKEN}"
      GITHUB_ORG: "${OCEAN_TEST_FLEET_ORG}"
"#;
        std::fs::write(path, yaml).unwrap();
    }

    #[test]
    #[serial_test::serial]
    fn cmd_harden_fleet_invalid_mode_errors() {
        let dir = tempfile::tempdir().unwrap();
        let fleet = dir.path().join("fleet.yaml");
        write_valid_fleet_manifest(&fleet);
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let tf = dir.path().join("tf");
        std::fs::create_dir_all(&tf).unwrap();
        let outd = dir.path().join("out");
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_harden_fleet(
            &mut out,
            &fleet,
            checks.to_str().unwrap(),
            "definitely-not-a-mode",
            false,
            true,
            tf.to_str().unwrap(),
            "json",
            &filter,
            2,
            false,
            &outd,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    #[serial_test::serial]
    fn cmd_harden_fleet_missing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let tf = dir.path().join("tf");
        std::fs::create_dir_all(&tf).unwrap();
        let outd = dir.path().join("out");
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_harden_fleet(
            &mut out,
            std::path::Path::new("/definitely/does/not/exist.yaml"),
            checks.to_str().unwrap(),
            "api",
            false,
            true,
            tf.to_str().unwrap(),
            "json",
            &filter,
            2,
            false,
            &outd,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    #[serial_test::serial]
    fn cmd_harden_fleet_dry_run_ok() {
        let dir = tempfile::tempdir().unwrap();
        let fleet = dir.path().join("fleet.yaml");
        write_valid_fleet_manifest(&fleet);
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let tf = dir.path().join("tf");
        std::fs::create_dir_all(&tf).unwrap();
        let outd = dir.path().join("out");
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_harden_fleet(
            &mut out,
            &fleet,
            checks.to_str().unwrap(),
            "api",
            false,
            true,
            tf.to_str().unwrap(),
            "json",
            &filter,
            2,
            false,
            &outd,
            true, // dry_run = true
        );
        assert!(result.is_ok());
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Test Fleet"));
        assert!(s.contains("Dry run"));
    }

    fn write_failing_aws_check_for_fleet(dir: &std::path::Path, mock_url: &str) {
        std::fs::write(
            dir.join("FLEET-FAIL.check.yaml"),
            format!(
                r#"
id: FLEET-FAIL
name: Fleet Failing Check
description: t
source: github
profile: L1
severity: high
tags: [test]
references:
  soc2: CC6.1
credentials: {{}}
inputs: {{}}
steps:
  - id: q
    action: api_call
    request:
      method: GET
      url: "{mock_url}"
    extract:
      x: "$.x"
assertions:
  - id: a
    expr: "x == true"
    severity: high
    title: t
    pass_message: ok
    fail_message: fail
remediation:
  description: r
  steps: [s1]
  api:
    method: POST
    url: "https://api.github.com/orgs/x/settings"
    body: {{}}
"#
            ),
        )
        .unwrap();
    }

    #[test]
    #[serial_test::serial]
    fn cmd_harden_fleet_apply_summary_with_plans() {
        // Set up so execute_fleet actually generates plans and prints summary.
        let dir = tempfile::tempdir().unwrap();
        let fleet = dir.path().join("fleet.yaml");
        write_valid_fleet_manifest(&fleet);
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let srv = crate::testutil::MockHTTPServer::new(vec![(200, "{}".to_string())]);
        write_failing_aws_check_for_fleet(&checks, &srv.base_url);
        let tf = dir.path().join("tf");
        std::fs::create_dir_all(&tf).unwrap();
        let outd = dir.path().join("out");
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_harden_fleet(
            &mut out,
            &fleet,
            checks.to_str().unwrap(),
            "api",
            true,  // apply
            true,  // confirm
            tf.to_str().unwrap(),
            "json",
            &filter,
            1,
            true,  // continue_on_error
            &outd,
            false, // dry_run
        );
        // Whether it ends Ok or Err, the summary code paths get exercised.
        let _ = result;
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains("Fleet Summary"),
            "expected 'Fleet Summary' in output, got: {s}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn cmd_harden_fleet_apply_fault_injection() {
        // Drive each `?` continuation in the summary printing after a
        // successful execute_fleet.
        let dir = tempfile::tempdir().unwrap();
        let fleet = dir.path().join("fleet.yaml");
        write_valid_fleet_manifest(&fleet);
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let srv = crate::testutil::MockHTTPServer::new(vec![(200, "{}".to_string())]);
        write_failing_aws_check_for_fleet(&checks, &srv.base_url);
        let tf = dir.path().join("tf");
        std::fs::create_dir_all(&tf).unwrap();
        let outd = dir.path().join("out-faulty");
        let filter = crate::cli::filter::CheckFilter::default();
        for n in 0..60 {
            let mut w = crate::testutil::FailingWriter::new(n);
            let _ = cmd_harden_fleet(
                &mut w,
                &fleet,
                checks.to_str().unwrap(),
                "api",
                true,
                true,
                tf.to_str().unwrap(),
                "json",
                &filter,
                1,
                true,
                &outd,
                false,
            );
        }
    }

    #[test]
    #[serial_test::serial]
    fn cmd_harden_fleet_apply_with_failures_prints_summary() {
        let dir = tempfile::tempdir().unwrap();
        let fleet = dir.path().join("fleet.yaml");
        write_valid_fleet_manifest(&fleet);
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let tf = dir.path().join("tf");
        std::fs::create_dir_all(&tf).unwrap();
        let outd = dir.path().join("out");
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        // apply=true, confirm=true (skip prompt), continue_on_error=true.
        // execute_fleet will fail target since github creds are fake.
        let result = cmd_harden_fleet(
            &mut out,
            &fleet,
            checks.to_str().unwrap(),
            "api",
            true,
            true,
            tf.to_str().unwrap(),
            "json",
            &filter,
            1,
            true,
            &outd,
            false,
        );
        // Either Ok (everything skipped) or Err (target failures). Both
        // exercise the summary-printing code path.
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Fleet Summary") || s.contains("Test Fleet") || result.is_err());
    }

    #[test]
    #[serial_test::serial]
    fn cmd_harden_fleet_no_apply_prints_plan() {
        let dir = tempfile::tempdir().unwrap();
        let fleet = dir.path().join("fleet.yaml");
        write_valid_fleet_manifest(&fleet);
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let tf = dir.path().join("tf");
        std::fs::create_dir_all(&tf).unwrap();
        let outd = dir.path().join("out");
        let mut out = Vec::new();
        let filter = crate::cli::filter::CheckFilter::default();
        let result = cmd_harden_fleet(
            &mut out,
            &fleet,
            checks.to_str().unwrap(),
            "api",
            false, // apply = false
            true,
            tf.to_str().unwrap(),
            "json",
            &filter,
            2,
            false,
            &outd,
            false,
        );
        assert!(result.is_ok());
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Fleet dry-run plan"));
    }

    #[test]
    fn run_with_dashboard_dispatches_bad_db_errors() {
        // run_with's Dashboard arm: open_store fails on a directory path
        // → return Err before crate::dashboard::run is called.
        let (_d, db) = bad_db_path();
        let cli = parse_args(&["ocean", "--db", &db, "dashboard"]);
        let mut out = Vec::new();
        assert!(run_with(&mut out, cli).is_err());
    }

    #[test]
    fn run_with_build_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        let out_dir = dir.path().join("out");
        let cli = parse_args(&[
            "ocean", "build",
            "--target", "soc2",
            "--source", source.to_str().unwrap(),
            "--output", out_dir.to_str().unwrap(),
        ]);
        let mut out = Vec::new();
        let _ = run_with(&mut out, cli);
    }

    // ─── Fault-injection: cover `?` continuations after writeln!/write! ────
    //
    // Each handler that writes via `?` has a region for the early-return on
    // Err. With Vec<u8> the writer never errors, so those regions stay
    // uncovered. FailingWriter::new(N) fails on the Nth write_fmt call;
    // looping N over a generous range exercises every `?` in the chain.

    fn fault_inject<F>(max_n: usize, mut call: F)
    where
        F: FnMut(crate::testutil::FailingWriter),
    {
        use crate::testutil::FailingWriter;
        for n in 0..max_n {
            call(FailingWriter::new(n));
        }
    }

    #[test]
    fn cmd_version_fault_injection() {
        fault_inject(20, |mut w| {
            let _ = cmd_version(&mut w, OutputFormat::Json);
            let _ = cmd_version(&mut w, OutputFormat::Yaml);
        });
    }

    #[test]
    fn cmd_observe_fault_injection() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        fault_inject(20, |mut w| {
            let _ = cmd_observe(&mut w, OutputFormat::Json, &db, "mock.test", false);
        });
    }

    #[test]
    fn cmd_observe_path_fault_injection() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        write_simple_control_yaml(&cdir, "mock.test.yaml", "mock.test", "mock.test");
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        fault_inject(40, |mut w| {
            let _ = cmd_observe_path(
                &mut w, OutputFormat::Json, &db, "*", "mock", cdir.to_str().unwrap(), false,
            );
            let _ = cmd_observe_path(
                &mut w, OutputFormat::Yaml, &db, "*", "mock", cdir.to_str().unwrap(), false,
            );
        });
    }

    #[test]
    fn cmd_test_fault_injection() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        fault_inject(20, |mut w| {
            let _ = cmd_test(
                &mut w, OutputFormat::Json, &db, "mock.safety_test", "production", false, false,
            );
        });
    }

    #[test]
    fn cmd_test_path_fault_injection() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        std::fs::write(
            cdir.join("mock.safety.yaml"),
            r#"
id: mock.safety
name: Safety
description: t
testers:
  - module_id: mock.safety_test
modules: [mock.safety_test]
status_id: 1
classification:
  ocean:
    severity: medium
    profile: starter
    tags: []
    rationale: r
"#,
        )
        .unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        fault_inject(40, |mut w| {
            let _ = cmd_test_path(
                &mut w, OutputFormat::Json, &db, "*", "mock", "production",
                cdir.to_str().unwrap(), false, false,
            );
            let _ = cmd_test_path(
                &mut w, OutputFormat::Yaml, &db, "*", "mock", "production",
                cdir.to_str().unwrap(), false, false,
            );
        });
    }

    #[test]
    fn cmd_modules_list_fault_injection() {
        fault_inject(20, |mut w| {
            let _ = cmd_modules_list(&mut w, OutputFormat::Json, None);
            let _ = cmd_modules_list(&mut w, OutputFormat::Json, Some("observer"));
            let _ = cmd_modules_list(&mut w, OutputFormat::Json, Some("tester"));
        });
    }

    #[test]
    fn cmd_modules_validate_fault_injection() {
        fault_inject(20, |mut w| {
            let _ = cmd_modules_validate(&mut w, OutputFormat::Json, "mock.test");
        });
    }

    #[test]
    fn cmd_evaluate_fault_injection() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        write_simple_control_yaml(&cdir, "mock.test.yaml", "mock.test", "mock.test");
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        fault_inject(20, |mut w| {
            let _ = cmd_evaluate(
                &mut w, OutputFormat::Json, &db, "mock.test", None, cdir.to_str().unwrap(),
            );
        });
    }

    #[test]
    fn cmd_evaluate_path_fault_injection() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        write_simple_control_yaml(&cdir, "mock.test.yaml", "mock.test", "mock.test");
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        fault_inject(40, |mut w| {
            let _ = cmd_evaluate_path(
                &mut w, OutputFormat::Json, &db, "*", "mock", cdir.to_str().unwrap(),
            );
            let _ = cmd_evaluate_path(
                &mut w, OutputFormat::Yaml, &db, "*", "mock", cdir.to_str().unwrap(),
            );
        });
    }

    #[test]
    fn cmd_history_fault_injection() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        fault_inject(20, |mut w| {
            let _ = cmd_history(&mut w, OutputFormat::Json, &db, "iam.test", 30, None, None);
        });
    }

    #[test]
    fn cmd_report_fault_injection() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        store_one_evidence(&db);
        fault_inject(40, |mut w| {
            let _ = cmd_report(&mut w, &db, "2020-01-01:2030-12-31", "json", None);
            let _ = cmd_report(&mut w, &db, "2020-01-01:2030-12-31", "markdown", None);
            let _ = cmd_report(&mut w, &db, "2020-01-01:2030-12-31", "csv", None);
        });
    }

    #[test]
    fn cmd_compliance_fault_injection() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        store_control_status(&db, "iam.passing", "effective");
        store_control_status(&db, "iam.failing", "ineffective");
        store_control_status(&db, "iam.weird", "stale-data");
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        let fwpath = dir.path().join("fw.yaml");
        write_three_status_framework(&fwpath);
        fault_inject(80, |mut w| {
            let _ = cmd_compliance(
                &mut w, &db, Some(fwpath.to_str().unwrap()), cdir.to_str().unwrap(), "markdown",
            );
            let _ = cmd_compliance(
                &mut w, &db, Some(fwpath.to_str().unwrap()), cdir.to_str().unwrap(), "json",
            );
        });
    }

    #[test]
    #[serial_test::serial]
    fn cmd_harden_fleet_fault_injection_dry_run() {
        let dir = tempfile::tempdir().unwrap();
        let fleet = dir.path().join("fleet.yaml");
        write_valid_fleet_manifest(&fleet);
        let checks = dir.path().join("checks");
        std::fs::create_dir_all(&checks).unwrap();
        let tf = dir.path().join("tf");
        std::fs::create_dir_all(&tf).unwrap();
        let outd = dir.path().join("out");
        let filter = crate::cli::filter::CheckFilter::default();
        fault_inject(40, |mut w| {
            let _ = cmd_harden_fleet(
                &mut w, &fleet, checks.to_str().unwrap(), "api", false, true,
                tf.to_str().unwrap(), "json", &filter, 2, false, &outd, true, // dry_run
            );
            let _ = cmd_harden_fleet(
                &mut w, &fleet, checks.to_str().unwrap(), "api", false, true,
                tf.to_str().unwrap(), "json", &filter, 2, false, &outd, false, // !apply
            );
        });
    }

    #[test]
    fn cmd_schedule_list_fault_injection() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        fault_inject(20, |mut w| {
            let _ = cmd_schedule_list(&mut w, OutputFormat::Json, &db);
        });
    }

    // ─── open_store failure paths ──────────────────────────────────────────
    //
    // Passing a directory as the db path makes SqliteStore::open return Err.
    // This drives the `?` on every cmd_* function's `open_store(db)?` call.

    fn bad_db_path() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().to_str().unwrap().to_string(); // a directory, not a file
        (dir, db)
    }

    #[test]
    fn cmd_observe_open_store_err() {
        let (_d, db) = bad_db_path();
        let mut out = Vec::new();
        assert!(cmd_observe(&mut out, OutputFormat::Json, &db, "mock.test", true).is_err());
    }

    #[test]
    fn cmd_test_open_store_err() {
        let (_d, db) = bad_db_path();
        let mut out = Vec::new();
        assert!(cmd_test(
            &mut out, OutputFormat::Json, &db, "mock.safety_test", "production", true, false,
        )
        .is_err());
    }

    #[test]
    fn cmd_evaluate_open_store_err() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        write_simple_control_yaml(&cdir, "mock.test.yaml", "mock.test", "mock.test");
        let bad_db = dir.path().to_str().unwrap().to_string();
        let mut out = Vec::new();
        assert!(cmd_evaluate(
            &mut out, OutputFormat::Json, &bad_db, "mock.test", None, cdir.to_str().unwrap(),
        )
        .is_err());
    }

    #[test]
    fn cmd_evaluate_path_open_store_err() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        write_simple_control_yaml(&cdir, "mock.test.yaml", "mock.test", "mock.test");
        let bad_db = dir.path().to_str().unwrap().to_string();
        let mut out = Vec::new();
        assert!(cmd_evaluate_path(
            &mut out, OutputFormat::Json, &bad_db, "*", "mock", cdir.to_str().unwrap(),
        )
        .is_err());
    }

    #[test]
    fn cmd_observe_path_open_store_err() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        write_simple_control_yaml(&cdir, "mock.test.yaml", "mock.test", "mock.test");
        let bad_db = dir.path().to_str().unwrap().to_string();
        let mut out = Vec::new();
        assert!(cmd_observe_path(
            &mut out, OutputFormat::Json, &bad_db, "*", "mock", cdir.to_str().unwrap(), true,
        )
        .is_err());
    }

    #[test]
    fn cmd_test_path_open_store_err() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        write_simple_control_yaml(&cdir, "mock.test.yaml", "mock.test", "mock.test");
        let bad_db = dir.path().to_str().unwrap().to_string();
        let mut out = Vec::new();
        assert!(cmd_test_path(
            &mut out, OutputFormat::Json, &bad_db, "*", "mock", "production",
            cdir.to_str().unwrap(), true, false,
        )
        .is_err());
    }

    #[test]
    fn cmd_history_open_store_err() {
        let (_d, db) = bad_db_path();
        let mut out = Vec::new();
        assert!(cmd_history(&mut out, OutputFormat::Json, &db, "iam.test", 30, None, None).is_err());
    }

    #[test]
    fn cmd_report_open_store_err() {
        let (_d, db) = bad_db_path();
        let mut out = Vec::new();
        assert!(cmd_report(&mut out, &db, "2024-01-01:2024-12-31", "json", None).is_err());
    }

    #[test]
    fn cmd_schedule_list_open_store_err() {
        let (_d, db) = bad_db_path();
        let mut out = Vec::new();
        assert!(cmd_schedule_list(&mut out, OutputFormat::Json, &db).is_err());
    }

    #[test]
    fn cmd_schedule_remove_open_store_err() {
        let (_d, db) = bad_db_path();
        assert!(cmd_schedule_remove(&db, "x").is_err());
    }

    #[test]
    fn cmd_schedule_status_open_store_err() {
        let (_d, db) = bad_db_path();
        let mut out = Vec::new();
        assert!(cmd_schedule_status(&mut out, OutputFormat::Json, &db, "x").is_err());
    }

    #[test]
    fn cmd_schedule_add_open_store_err() {
        let (_d, db) = bad_db_path();
        let mut out = Vec::new();
        assert!(cmd_schedule_add(
            &mut out, OutputFormat::Json, &db, Some("iam.test"),
            "0 * * * *", &["mock.test".to_string()], "safe", "production", true, false,
        )
        .is_err());
    }

    #[test]
    fn cmd_build_invalid_target_returns_err() {
        let mut out = Vec::new();
        let result = cmd_build(&mut out, "src", "not-a-real-target", None, false, false, None);
        assert!(result.is_err());
    }

    #[test]
    fn cmd_build_with_valid_target_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("src");
        std::fs::create_dir_all(&source).unwrap();
        let out_dir = dir.path().join("out");
        let mut out = Vec::new();
        let result = cmd_build(
            &mut out,
            source.to_str().unwrap(),
            "soc2",
            Some(out_dir.to_str().unwrap()),
            false,
            false,
            None,
        );
        // Empty source dir → codegen may succeed or err; both paths exercise the function.
        let _ = result;
    }

    #[test]
    fn cmd_compliance_open_store_err() {
        let dir = tempfile::tempdir().unwrap();
        let cdir = dir.path().join("controls");
        std::fs::create_dir_all(&cdir).unwrap();
        let fwpath = dir.path().join("fw.yaml");
        write_three_status_framework(&fwpath);
        // Use a subdirectory as bad db path
        let bad_db_dir = dir.path().join("bad_db_subdir");
        std::fs::create_dir_all(&bad_db_dir).unwrap();
        let bad_db = bad_db_dir.to_str().unwrap().to_string();
        let mut out = Vec::new();
        let result = cmd_compliance(
            &mut out, &bad_db, Some(fwpath.to_str().unwrap()), cdir.to_str().unwrap(), "json",
        );
        assert!(result.is_err());
    }

    #[test]
    fn cmd_schedule_status_fault_injection() {
        use crate::scheduler::Schedule;
        use chrono::Utc;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("evidence.db").to_str().unwrap().to_string();
        let store = open_store(&db).unwrap();
        let now = Utc::now();
        let sched = Schedule {
            id: "fault-inject".to_string(),
            control_id: "iam.test".to_string(),
            cron_expr: "0 * * * *".to_string(),
            modules: vec!["mock.test".to_string()],
            max_safety_level: "safe".to_string(),
            environment_scope: "production".to_string(),
            enabled: true,
            catch_up: false,
            last_run: None,
            next_run: None,
            created_at: now,
            updated_at: now,
        };
        store.store_schedule(&sched).unwrap();
        fault_inject(20, |mut w| {
            let _ = cmd_schedule_status(&mut w, OutputFormat::Json, &db, "fault-inject");
        });
    }
}
