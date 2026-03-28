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

use ocean::{
    check::loader::load_all_checks,
    codegen::{generate as codegen_generate, BuildTarget},
    control::{
        calculate_uptime, evaluate_composite, evaluate_control, ComponentResult, Control,
        Framework, ModuleRef,
    },
    harden::{
        execute_plans, plan_harden, print_dry_run as harden_print_dry_run,
        print_results as harden_print_results, RemediationMode,
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
    },

    /// Remediate failing controls using API calls or Terraform.
    Harden {
        /// Remediation mode: api (default), terraform, cli, all.
        #[arg(long, default_value = "api")]
        mode: String,

        /// Apply remediation (without this flag, shows dry-run plan).
        #[arg(long)]
        apply: bool,

        /// Filter checks by ID prefix or source system (e.g., GH, github).
        #[arg(long)]
        control: Option<String>,

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
    let format = OutputFormat::from_str(&cli.format);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let command = cli.command.unwrap_or(Commands::Dashboard {
        refresh: 30,
        controls_dir: "controls".to_string(),
    });

    match command {
        Commands::Version => cmd_version(&mut out, format),
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
                cmd_observe_path(&mut out, format, &cli.db, t, p, &controls_dir, !no_store)
            } else if let Some(m) = module.as_deref() {
                cmd_observe(&mut out, format, &cli.db, m, !no_store)
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
                cmd_test_path(&mut out, format, &cli.db, t, p, &env, &controls_dir, !no_store, confirm)
            } else if let Some(m) = module.as_deref() {
                cmd_test(&mut out, format, &cli.db, m, &env, !no_store, confirm)
            } else {
                Err(anyhow!(
                    "Specify a module ID or use --target/-t and --control/-c"
                ))
            }
        }
        Commands::Modules { cmd } => match cmd {
            ModulesCmd::List { module_type } => {
                cmd_modules_list(&mut out, format, module_type.as_deref())
            }
            ModulesCmd::Validate { id } => cmd_modules_validate(&mut out, format, &id),
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
                cmd_evaluate_path(&mut out, format, &cli.db, t, p, &controls_dir)
            } else if let Some(ctrl) = control.as_deref() {
                cmd_evaluate(&mut out, format, &cli.db, ctrl, cel.as_deref(), &controls_dir)
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
            framework,
            checks_dir,
            include_passing,
            format: rep_fmt,
            control,
            tags,
            severity,
            profile,
        } => {
            let check_filter = filter::CheckFilter {
                tags: tags.map(|t| filter::parse_csv(&t)).unwrap_or_default(),
                severities: severity.map(|s| filter::parse_csv(&s)).unwrap_or_default(),
                profile,
            };
            if let Some(frameworks) = framework {
                cmd_report_framework(
                    &mut out,
                    &checks_dir,
                    &frameworks,
                    include_passing,
                    &rep_fmt,
                    &check_filter,
                )
            } else {
                let p = period.ok_or_else(|| {
                    anyhow!("--period YYYY-MM-DD:YYYY-MM-DD is required when --framework is not specified")
                })?;
                cmd_report(&mut out, &cli.db, &p, &rep_fmt, control.as_deref())
            }
        }
        Commands::Harden {
            mode,
            apply,
            control,
            checks_dir,
            terraform_dir,
            format: harden_fmt,
            tags,
            severity,
            profile,
        } => {
            let check_filter = filter::CheckFilter {
                tags: tags.map(|t| filter::parse_csv(&t)).unwrap_or_default(),
                severities: severity.map(|s| filter::parse_csv(&s)).unwrap_or_default(),
                profile,
            };
            cmd_harden(
                &mut out,
                &checks_dir,
                &mode,
                apply,
                control.as_deref(),
                &terraform_dir,
                &harden_fmt,
                &check_filter,
            )
        }
        Commands::Build {
            target,
            source,
            output,
            validate,
            diff,
            filter,
        } => cmd_build(
            &mut out,
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
        Commands::Dashboard {
            refresh,
            controls_dir,
        } => {
            let store = open_store(&cli.db)?;
            ocean::dashboard::run(&store, &controls_dir, refresh)
        }
        Commands::Compliance {
            framework,
            controls_dir,
            format: fmt,
        } => cmd_compliance(&mut out, &cli.db, framework.as_deref(), &controls_dir, &fmt),
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

    let authorizer: Box<dyn ocean::module::Authorizer> = if confirm {
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
                        evaluation_logic: ocean::control::EvaluationLogic::default(),
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
            let authorizer: Box<dyn ocean::module::Authorizer> = if confirm {
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
    rt.block_on(ocean::api::server::serve(
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
) -> Result<()> {
    use ocean::check::definition::StringOrVec;

    let dir = std::path::Path::new(checks_dir);
    let all_defs = ocean::check::loader::load_definitions_from_dir(dir);
    let defs: Vec<_> = if check_filter.is_empty() {
        all_defs
    } else {
        all_defs.into_iter().filter(|d| check_filter.matches(d)).collect()
    };

    if defs.is_empty() {
        writeln!(out, "No checks found in '{checks_dir}'")?;
        return Ok(());
    }

    let registry = build_registry();
    let executor = Executor::new(registry);
    let config = env_as_config();

    // Normalize requested frameworks.
    let all_fws = ["soc2", "nist", "iso27001", "pci-dss", "disa-stig"];
    let requested: Vec<&str> = if frameworks.iter().any(|f| f == "all") {
        all_fws.to_vec()
    } else {
        frameworks.iter().map(String::as_str).collect()
    };

    #[derive(serde::Serialize)]
    struct FrameworkRow {
        framework: String,
        control_ref: String,
        check_id: String,
        check_name: String,
        status: String,
    }

    let mut rows: Vec<FrameworkRow> = Vec::new();
    let mut sarif_results: Vec<sarif::CheckResult> = Vec::new();

    for def in &defs {
        // Run the check (passive only; skip active).
        if def.check_type != ocean::check::definition::CheckType::Passive {
            continue;
        }

        let status = match executor.execute_observer(&def.id, &config) {
            Ok(evidence) => {
                let any_fail = evidence
                    .iter()
                    .any(|e| matches!(e.status_id, ocean::StatusId::Ineffective));
                if any_fail {
                    "FAIL"
                } else {
                    "PASS"
                }
            }
            Err(_) => "ERROR",
        };

        // Collect SARIF results for all checks (SARIF filters internally).
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

        if !include_passing && status == "PASS" {
            continue;
        }

        let refs = &def.references;
        let mapping: &[(&str, &StringOrVec)] = &[
            ("soc2", &refs.soc2),
            ("nist", &refs.nist),
            ("iso27001", &refs.iso27001),
            ("pci-dss", &refs.pci_dss),
            ("disa-stig", &refs.disa_stig),
        ];

        for (fw_name, fw_refs) in mapping {
            if !requested.contains(fw_name) {
                continue;
            }
            for control_ref in fw_refs.as_vec() {
                rows.push(FrameworkRow {
                    framework: fw_name.to_string(),
                    control_ref,
                    check_id: def.id.clone(),
                    check_name: def.name.clone(),
                    status: status.to_string(),
                });
            }
        }
    }

    match format.to_lowercase().as_str() {
        "sarif" => {
            let sarif_log = sarif::build_sarif(&defs, &sarif_results);
            sarif::write_sarif(out, &sarif_log)?;
        }
        "json" => {
            writeln!(out, "{}", serde_json::to_string_pretty(&rows)?)?;
        }
        "csv" => {
            writeln!(out, "framework,control_ref,check_id,check_name,status")?;
            for r in &rows {
                writeln!(
                    out,
                    "{},{},{},{},{}",
                    r.framework, r.control_ref, r.check_id, r.check_name, r.status
                )?;
            }
        }
        _ => {
            // Table output grouped by framework.
            let mut by_fw: std::collections::BTreeMap<&str, Vec<&FrameworkRow>> =
                std::collections::BTreeMap::new();
            for r in &rows {
                by_fw.entry(r.framework.as_str()).or_default().push(r);
            }
            for (fw, fw_rows) in &by_fw {
                writeln!(out, "\n{} Compliance Report", fw.to_uppercase())?;
                writeln!(out, "{:-<60}", "")?;
                writeln!(out, "{:<12} {:<8} {:<12} {}", "Control", "Status", "Check", "Name")?;
                writeln!(out, "{:-<60}", "")?;
                for r in fw_rows {
                    writeln!(
                        out,
                        "{:<12} {:<8} {:<12} {}",
                        r.control_ref, r.status, r.check_id, r.check_name
                    )?;
                }
            }
            if rows.is_empty() {
                writeln!(out, "No framework mappings found for the specified frameworks.")?;
            }
        }
    }
    Ok(())
}

// ─── ocean harden ─────────────────────────────────────────────────────────────

fn cmd_harden<W: Write>(
    out: &mut W,
    checks_dir: &str,
    mode: &str,
    apply: bool,
    id_filter: Option<&str>,
    terraform_dir: &str,
    format: &str,
    check_filter: &filter::CheckFilter,
) -> Result<()> {
    let dir = std::path::Path::new(checks_dir);
    let rem_mode = RemediationMode::from_str(mode)?;
    let config = env_as_config();

    let mut plans = plan_harden(dir, &rem_mode, &config, id_filter)?;
    if !check_filter.is_empty() {
        // Load definitions to apply tag/severity/profile filter.
        let defs = ocean::check::loader::load_definitions_from_dir(dir);
        let allowed: std::collections::HashSet<String> = defs
            .iter()
            .filter(|d| check_filter.matches(d))
            .map(|d| d.id.clone())
            .collect();
        plans.retain(|p| allowed.contains(&p.check_id));
    }

    if !apply {
        harden_print_dry_run(out, &plans, format)?;
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
    harden_print_results(out, &results, format)?;

    let failures = results.iter().filter(|r| !r.success).count();
    if failures > 0 {
        return Err(anyhow!("{failures} remediation(s) failed"));
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
}
