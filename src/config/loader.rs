use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ServerConfig
// ---------------------------------------------------------------------------

fn default_port() -> u16 {
    8080
}

/// Configuration for the OCEAN REST API server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    /// Bearer token required for all API requests. Empty = no auth.
    #[serde(default)]
    pub auth_token: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            auth_token: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// The operator's home directory, or `.` when the platform names none.
fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// `~/.ocean` — the directory OCEAN owns for per-user state.
fn ocean_home() -> PathBuf {
    home_dir().join(".ocean")
}

fn default_storage_path() -> String {
    ocean_home().join("ocean.db").to_string_lossy().into_owned()
}

fn default_controls_dir() -> String {
    "controls".to_string()
}

fn default_output_format() -> String {
    "json".to_string()
}

/// Full OCEAN configuration — loaded from YAML file with env var overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path to the SQLite evidence database.
    #[serde(default = "default_storage_path")]
    pub storage_path: String,

    /// Directory containing control YAML definitions.
    #[serde(default = "default_controls_dir")]
    pub controls_dir: String,

    /// Default output format: "json" or "yaml".
    #[serde(default = "default_output_format")]
    pub output_format: String,

    /// HTTP server configuration.
    #[serde(default)]
    pub server: ServerConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            storage_path: default_storage_path(),
            controls_dir: default_controls_dir(),
            output_format: default_output_format(),
            server: ServerConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/// Where a configuration path came from.
///
/// Provenance decides whether a containment base exists. A path the operator
/// names is deliberate and has no base to be contained by; the default path is
/// derived by OCEAN itself and is contained by `~/.ocean`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConfigOrigin {
    /// Named by the operator: the `path` argument or `OCEAN_CONFIG`.
    Operator,
    /// Derived from `~/.ocean/config.yaml`, and contained by that directory.
    Default { base: PathBuf },
}

/// Decide which configuration file to read and record where the path came from.
fn resolve_config_path(path: Option<&str>) -> (PathBuf, ConfigOrigin) {
    if let Some(p) = path {
        return (PathBuf::from(p), ConfigOrigin::Operator);
    }
    if let Ok(p) = std::env::var("OCEAN_CONFIG") {
        return (PathBuf::from(p), ConfigOrigin::Operator);
    }
    let base = ocean_home();
    let path = base.join("config.yaml");
    (path, ConfigOrigin::Default { base })
}

/// Resolve a configuration path to a canonical, existing regular file.
///
/// `Ok(None)` means no file lives there — an absent config file is not an
/// error, the caller falls back to defaults. Every other outcome fails closed
/// with the reason:
///
/// - a path that cannot be resolved (unreadable parent, symlink loop) is
///   reported instead of being retried against the filesystem;
/// - a path that resolves to something other than a regular file (a directory,
///   a device, a FIFO) is refused before it is opened;
/// - a path from the default location that resolves *outside* `~/.ocean` is
///   refused, because the only way to get there is a symlink planted in
///   OCEAN's own directory — the move that turns "read my config" into "read
///   `~/.ssh/id_ed25519` and print its bytes back in a YAML parse error".
///
/// Resolving once and reading the resolved path also closes the check-then-use
/// gap: the file that was verified is the file that gets opened.
fn resolve_config_file(cfg_path: &Path, origin: &ConfigOrigin) -> Result<Option<PathBuf>> {
    let resolved = match std::fs::canonicalize(cfg_path) {
        Ok(resolved) => resolved,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e).with_context(|| format!("resolve config file '{}'", cfg_path.display()))
        }
    };

    let meta = std::fs::metadata(&resolved)
        .with_context(|| format!("stat config file '{}'", resolved.display()))?;
    if !meta.is_file() {
        bail!("config path '{}' is not a regular file", resolved.display());
    }

    if let ConfigOrigin::Default { base } = origin {
        let root = std::fs::canonicalize(base)
            .with_context(|| format!("resolve OCEAN config directory '{}'", base.display()))?;
        if !resolved.starts_with(&root) {
            bail!(
                "config file '{}' resolves to '{}', outside '{}'",
                cfg_path.display(),
                resolved.display(),
                root.display()
            );
        }
    }

    Ok(Some(resolved))
}

/// Load configuration from a YAML file, then apply environment variable overrides.
///
/// Search order:
/// 1. `path` argument if provided
/// 2. `OCEAN_CONFIG` env var
/// 3. `~/.ocean/config.yaml` (default)
///
/// Whichever path wins is resolved before it is opened — see
/// [`resolve_config_file`] for what is refused and why. A missing file is not
/// an error; the defaults below stand and the environment still overrides them.
///
/// Environment overrides (applied after file load):
/// - `OCEAN_DB`           → `storage_path`
/// - `OCEAN_CONTROLS_DIR` → `controls_dir`
/// - `OCEAN_PORT`         → `server.port`
/// - `OCEAN_AUTH_TOKEN`   → `server.auth_token`
pub fn load(path: Option<&str>) -> Result<Config> {
    let (cfg_path, origin) = resolve_config_path(path);

    let mut config = match resolve_config_file(&cfg_path, &origin)? {
        Some(resolved) => {
            let yaml = std::fs::read_to_string(&resolved)
                .with_context(|| format!("read config file '{}'", resolved.display()))?;
            serde_yaml::from_str(&yaml)
                .with_context(|| format!("parse config YAML '{}'", resolved.display()))?
        }
        None => Config::default(),
    };

    // Apply environment variable overrides.
    if let Ok(val) = std::env::var("OCEAN_DB") {
        if !val.is_empty() {
            config.storage_path = val;
        }
    }
    if let Ok(val) = std::env::var("OCEAN_CONTROLS_DIR") {
        if !val.is_empty() {
            config.controls_dir = val;
        }
    }
    if let Ok(val) = std::env::var("OCEAN_PORT") {
        if let Ok(port) = val.parse::<u16>() {
            config.server.port = port;
        }
    }
    if let Ok(val) = std::env::var("OCEAN_AUTH_TOKEN") {
        if !val.is_empty() {
            config.server.auth_token = val;
        }
    }

    Ok(config)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn default_config_has_sensible_values() {
        let cfg = Config::default();
        assert!(cfg.storage_path.contains(".ocean"));
        assert_eq!(cfg.controls_dir, "controls");
        assert_eq!(cfg.output_format, "json");
        assert_eq!(cfg.server.port, 8080);
        assert!(cfg.server.auth_token.is_empty());
    }

    #[test]
    fn load_returns_defaults_when_no_file() {
        // Point at a path that does not exist inside a private temp dir —
        // an absent config file must fall back to defaults, not error.
        let tmp = tempfile::TempDir::new().unwrap();
        let missing = tmp.path().join("ocean_nonexistent_config.yaml");
        let cfg = load(Some(missing.to_str().unwrap())).unwrap();
        assert_eq!(cfg.server.port, 8080);
        assert_eq!(cfg.controls_dir, "controls");
    }

    // Exercises the default-path closure at lines 103-108: when no path is
    // passed and OCEAN_CONFIG isn't set, load() computes
    // `${HOME}/.ocean/config.yaml`. We don't assert on the result (the file
    // probably doesn't exist in CI, so defaults will be returned) — the test
    // just guarantees the closure runs.
    #[test]
    #[serial_test::serial]
    fn load_default_path_closure_runs_when_no_path_and_no_env() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        // Save / unset OCEAN_CONFIG so the second branch fires.
        let saved = std::env::var("OCEAN_CONFIG").ok();
        std::env::remove_var("OCEAN_CONFIG");

        let _ = load(None);

        if let Some(v) = saved {
            std::env::set_var("OCEAN_CONFIG", v);
        }
    }

    #[test]
    #[serial_test::serial]
    fn load_default_path_closure_with_userprofile_fallback() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        // Exercises the .or_else(|_| std::env::var("USERPROFILE")) branch.
        // Save current HOME / OCEAN_CONFIG, unset HOME, set USERPROFILE.
        let saved_home = std::env::var("HOME").ok();
        let saved_userprofile = std::env::var("USERPROFILE").ok();
        let saved_ocean = std::env::var("OCEAN_CONFIG").ok();
        std::env::remove_var("OCEAN_CONFIG");
        std::env::remove_var("HOME");
        std::env::set_var("USERPROFILE", "/tmp/_ocean_userprofile_only");

        let _ = load(None);

        // Restore.
        std::env::remove_var("USERPROFILE");
        if let Some(v) = saved_userprofile {
            std::env::set_var("USERPROFILE", v);
        }
        if let Some(v) = saved_home {
            std::env::set_var("HOME", v);
        }
        if let Some(v) = saved_ocean {
            std::env::set_var("OCEAN_CONFIG", v);
        }
    }

    #[test]
    #[serial_test::serial]
    fn load_default_path_closure_with_no_home_no_userprofile() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        // Final fallback: "." when neither HOME nor USERPROFILE is set.
        let saved_home = std::env::var("HOME").ok();
        let saved_userprofile = std::env::var("USERPROFILE").ok();
        let saved_ocean = std::env::var("OCEAN_CONFIG").ok();
        std::env::remove_var("OCEAN_CONFIG");
        std::env::remove_var("HOME");
        std::env::remove_var("USERPROFILE");

        let _ = load(None);

        if let Some(v) = saved_userprofile {
            std::env::set_var("USERPROFILE", v);
        }
        if let Some(v) = saved_home {
            std::env::set_var("HOME", v);
        }
        if let Some(v) = saved_ocean {
            std::env::set_var("OCEAN_CONFIG", v);
        }
    }

    #[test]
    fn load_parses_yaml_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp
            .path()
            .join(format!("ocean_cfg_test_{}.yaml", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string();

        std::fs::write(
            &path,
            r#"
storage_path: /var/lib/ocean/test.db
controls_dir: /etc/ocean/controls
output_format: yaml
server:
  port: 9090
  auth_token: "secret"
"#,
        )
        .unwrap();

        let cfg = load(Some(&path)).unwrap();
        assert_eq!(cfg.storage_path, "/var/lib/ocean/test.db");
        assert_eq!(cfg.controls_dir, "/etc/ocean/controls");
        assert_eq!(cfg.output_format, "yaml");
        assert_eq!(cfg.server.port, 9090);
        assert_eq!(cfg.server.auth_token, "secret");
    }

    #[test]
    fn config_serde_round_trip() {
        let cfg = Config {
            storage_path: "/db/test.db".to_string(),
            controls_dir: "ctrl".to_string(),
            output_format: "yaml".to_string(),
            server: ServerConfig {
                port: 1234,
                auth_token: "tok".to_string(),
            },
        };
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        let decoded: Config = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(decoded.storage_path, "/db/test.db");
        assert_eq!(decoded.server.port, 1234);
    }

    #[test]
    fn default_server_config() {
        let sc = ServerConfig::default();
        assert_eq!(sc.port, 8080);
        assert!(sc.auth_token.is_empty());
    }

    // --- env var overrides (serialized via ENV_MUTEX to avoid races) ---

    fn with_env<F: FnOnce()>(key: &str, val: &str, f: F) {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let old = std::env::var(key).ok();
        std::env::set_var(key, val);
        f();
        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn ocean_db_env_overrides_storage_path() {
        with_env("OCEAN_DB", "/tmp/custom_test_ocean.db", || {
            let cfg = load(Some("/tmp/ocean_nonexistent_xyz.yaml")).unwrap();
            assert_eq!(cfg.storage_path, "/tmp/custom_test_ocean.db");
        });
    }

    #[test]
    fn ocean_db_empty_string_does_not_override() {
        with_env("OCEAN_DB", "", || {
            let cfg = load(Some("/tmp/ocean_nonexistent_xyz.yaml")).unwrap();
            assert!(cfg.storage_path.contains(".ocean") || !cfg.storage_path.is_empty());
        });
    }

    #[test]
    fn ocean_controls_dir_env_overrides() {
        with_env("OCEAN_CONTROLS_DIR", "/tmp/custom_controls", || {
            let cfg = load(Some("/tmp/ocean_nonexistent_xyz.yaml")).unwrap();
            assert_eq!(cfg.controls_dir, "/tmp/custom_controls");
        });
    }

    #[test]
    fn ocean_controls_dir_empty_does_not_override() {
        with_env("OCEAN_CONTROLS_DIR", "", || {
            let cfg = load(Some("/tmp/ocean_nonexistent_xyz.yaml")).unwrap();
            assert_eq!(cfg.controls_dir, "controls");
        });
    }

    #[test]
    fn ocean_port_env_overrides_server_port() {
        with_env("OCEAN_PORT", "9999", || {
            let cfg = load(Some("/tmp/ocean_nonexistent_xyz.yaml")).unwrap();
            assert_eq!(cfg.server.port, 9999);
        });
    }

    #[test]
    fn ocean_port_invalid_does_not_override() {
        with_env("OCEAN_PORT", "not_a_number", || {
            let cfg = load(Some("/tmp/ocean_nonexistent_xyz.yaml")).unwrap();
            assert_eq!(cfg.server.port, 8080);
        });
    }

    #[test]
    fn ocean_auth_token_env_overrides() {
        with_env("OCEAN_AUTH_TOKEN", "my-secret-token", || {
            let cfg = load(Some("/tmp/ocean_nonexistent_xyz.yaml")).unwrap();
            assert_eq!(cfg.server.auth_token, "my-secret-token");
        });
    }

    #[test]
    fn ocean_auth_token_empty_does_not_override() {
        with_env("OCEAN_AUTH_TOKEN", "", || {
            let cfg = load(Some("/tmp/ocean_nonexistent_xyz.yaml")).unwrap();
            assert!(cfg.server.auth_token.is_empty());
        });
    }

    #[test]
    fn default_storage_path_uses_home_or_userprofile() {
        // default_storage_path() falls back to HOME or USERPROFILE, or "."
        // We just verify the default path ends with ocean.db
        let cfg = Config::default();
        assert!(
            cfg.storage_path.ends_with("ocean.db"),
            "storage_path should end with ocean.db, got: {}",
            cfg.storage_path
        );
    }

    // ── Path resolution ─────────────────────────────────────────────────────

    #[test]
    fn explicit_path_is_operator_origin() {
        let (path, origin) = resolve_config_path(Some("/etc/ocean/config.yaml"));
        assert_eq!(path, PathBuf::from("/etc/ocean/config.yaml"));
        assert_eq!(origin, ConfigOrigin::Operator);
    }

    #[test]
    fn absent_config_file_resolves_to_none() {
        let tmp = tempfile::TempDir::new().unwrap();
        let missing = tmp.path().join("not-here.yaml");
        let resolved = resolve_config_file(&missing, &ConfigOrigin::Operator).unwrap();
        assert!(resolved.is_none(), "absent file must not be an error");
    }

    #[test]
    fn directory_is_refused_as_config_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let err = resolve_config_file(tmp.path(), &ConfigOrigin::Operator)
            .expect_err("a directory is not a config file");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not a regular file"),
            "error should name the reason: {msg}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn load_via_ocean_config_env_var() {
        // tempfile::TempDir gives a 0700, unpredictably-named directory instead
        // of the shared world-writable temp base (predictable-name/symlink race).
        // .keep() hands back the PathBuf; the directory lives for the test binary.
        let dir = tempfile::TempDir::new().unwrap().keep();
        let path = dir
            .join(format!("ocean_env_cfg_{}.yaml", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string();

        std::fs::write(
            &path,
            "storage_path: /tmp/envvar.db\ncontrols_dir: envcontrols\noutput_format: yaml\n",
        )
        .unwrap();

        let key = "OCEAN_CONFIG";
        let old = std::env::var(key).ok();
        std::env::set_var(key, &path);

        // Pass None so the env var is used
        let cfg = load(None).unwrap();
        assert_eq!(cfg.storage_path, "/tmp/envvar.db");
        assert_eq!(cfg.controls_dir, "envcontrols");

        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_bad_yaml_returns_error() {
        // tempfile::TempDir gives a 0700, unpredictably-named directory instead
        // of the shared world-writable temp base (predictable-name/symlink race).
        // .keep() hands back the PathBuf; the directory lives for the test binary.
        let dir = tempfile::TempDir::new().unwrap().keep();
        let path = dir
            .join(format!("ocean_bad_cfg_{}.yaml", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string();
        std::fs::write(&path, "port: [invalid yaml structure").unwrap();
        let result = load(Some(&path));
        assert!(result.is_err(), "bad YAML should return an error");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_refuses_directory_as_config_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let err =
            load(Some(tmp.path().to_str().unwrap())).expect_err("a directory is not a config file");
        assert!(format!("{err:#}").contains("not a regular file"));
    }

    #[test]
    fn resolved_config_file_is_canonical() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("config.yaml");
        std::fs::write(&path, "output_format: yaml\n").unwrap();

        // A traversal-shaped but in-tree path collapses to the real file.
        let winding = tmp.path().join("sub").join("..").join("config.yaml");
        std::fs::create_dir(tmp.path().join("sub")).unwrap();

        let resolved = resolve_config_file(&winding, &ConfigOrigin::Operator)
            .unwrap()
            .expect("file exists");
        assert_eq!(resolved, std::fs::canonicalize(&path).unwrap());
        assert!(!resolved.to_string_lossy().contains(".."));
    }

    #[cfg(unix)]
    #[test]
    fn default_origin_refuses_symlink_escaping_ocean_home() {
        let tmp = tempfile::TempDir::new().unwrap();
        let base = tmp.path().join("dot-ocean");
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&base).unwrap();
        std::fs::create_dir(&outside).unwrap();

        let secret = outside.join("secret.yaml");
        std::fs::write(&secret, "output_format: yaml\n").unwrap();

        let link = base.join("config.yaml");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let origin = ConfigOrigin::Default { base: base.clone() };
        let err = resolve_config_file(&link, &origin)
            .expect_err("a symlink out of ~/.ocean must be refused");
        let msg = format!("{err:#}");
        assert!(msg.contains("outside"), "error should say why: {msg}");
    }

    #[cfg(unix)]
    #[test]
    fn default_origin_accepts_file_inside_ocean_home() {
        let tmp = tempfile::TempDir::new().unwrap();
        let base = tmp.path().join("dot-ocean");
        std::fs::create_dir(&base).unwrap();
        let path = base.join("config.yaml");
        std::fs::write(&path, "output_format: yaml\n").unwrap();

        let origin = ConfigOrigin::Default { base: base.clone() };
        let resolved = resolve_config_file(&path, &origin)
            .unwrap()
            .expect("file exists");
        assert_eq!(resolved, std::fs::canonicalize(&path).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn operator_origin_may_point_anywhere() {
        // An operator naming a path explicitly is deliberate: containment is
        // only enforced for the path OCEAN derives on its own.
        let tmp = tempfile::TempDir::new().unwrap();
        let base = tmp.path().join("dot-ocean");
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&base).unwrap();
        std::fs::create_dir(&outside).unwrap();

        let target = outside.join("elsewhere.yaml");
        std::fs::write(&target, "output_format: yaml\n").unwrap();
        let link = base.join("config.yaml");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let resolved = resolve_config_file(&link, &ConfigOrigin::Operator)
            .unwrap()
            .expect("file exists");
        assert_eq!(resolved, std::fs::canonicalize(&target).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_is_treated_as_absent() {
        let tmp = tempfile::TempDir::new().unwrap();
        let link = tmp.path().join("config.yaml");
        std::os::unix::fs::symlink(tmp.path().join("gone.yaml"), &link).unwrap();

        let resolved = resolve_config_file(&link, &ConfigOrigin::Operator).unwrap();
        assert!(resolved.is_none(), "dangling link means no config file");
    }
}
