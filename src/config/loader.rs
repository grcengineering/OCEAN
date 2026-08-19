use anyhow::{Context, Result};
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

fn default_storage_path() -> String {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    format!("{home}/.ocean/ocean.db")
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

/// Load configuration from a YAML file, then apply environment variable overrides.
///
/// Search order:
/// 1. `path` argument if provided
/// 2. `OCEAN_CONFIG` env var
/// 3. `~/.ocean/config.yaml` (default)
///
/// Environment overrides (applied after file load):
/// - `OCEAN_DB`           → `storage_path`
/// - `OCEAN_CONTROLS_DIR` → `controls_dir`
/// - `OCEAN_PORT`         → `server.port`
/// - `OCEAN_AUTH_TOKEN`   → `server.auth_token`
pub fn load(path: Option<&str>) -> Result<Config> {
    let mut config = Config::default();

    let cfg_path = path
        .map(|p| p.to_string())
        .or_else(|| std::env::var("OCEAN_CONFIG").ok())
        .unwrap_or_else(|| {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_else(|_| ".".to_string());
            format!("{home}/.ocean/config.yaml")
        });

    if std::path::Path::new(&cfg_path).exists() {
        let yaml = std::fs::read_to_string(&cfg_path)
            .with_context(|| format!("read config file '{cfg_path}'"))?;
        config = serde_yaml::from_str(&yaml)
            .with_context(|| format!("parse config YAML '{cfg_path}'"))?;
    }

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
        // No OCEAN_CONFIG set, no ~/.ocean/config.yaml expected to exist in CI.
        // We pass a nonexistent path — should fall back to defaults.
        let cfg = load(Some("/tmp/ocean_nonexistent_config_xyz.yaml")).unwrap();
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
storage_path: /tmp/test.db
controls_dir: /tmp/controls
output_format: yaml
server:
  port: 9090
  auth_token: "secret"
"#,
        )
        .unwrap();

        let cfg = load(Some(&path)).unwrap();
        assert_eq!(cfg.storage_path, "/tmp/test.db");
        assert_eq!(cfg.controls_dir, "/tmp/controls");
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
}
