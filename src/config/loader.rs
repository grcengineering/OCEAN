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

    #[test]
    fn load_parses_yaml_file() {
        let dir = std::env::temp_dir();
        let path = dir
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

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn config_serde_round_trip() {
        let cfg = Config {
            storage_path: "/db/test.db".to_string(),
            controls_dir: "ctrl".to_string(),
            output_format: "yaml".to_string(),
            server: ServerConfig { port: 1234, auth_token: "tok".to_string() },
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
}
