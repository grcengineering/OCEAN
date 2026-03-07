// Shared GitHub API utilities for all GitHub observers and testers.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

pub const DEFAULT_GITHUB_API: &str = "https://api.github.com";
pub const GITHUB_API_VERSION: &str = "2022-11-28";

/// Performs an authenticated GET to the GitHub REST API v3.
/// `base_url` is `https://api.github.com` by default; tests override it.
pub fn github_get(token: &str, base_url: &str, path: &str) -> Result<(Value, u16)> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    let resp = ureq::get(&url)
        .set("Accept", "application/vnd.github+json")
        .set("Authorization", &format!("Bearer {}", token))
        .set("X-GitHub-Api-Version", GITHUB_API_VERSION)
        .call();

    match resp {
        Ok(r) => {
            let status = r.status();
            let body: Value = r
                .into_json()
                .map_err(|e| anyhow!("parsing GitHub JSON: {}", e))?;
            Ok((body, status))
        }
        Err(ureq::Error::Status(code, r)) => {
            let body: Value = r
                .into_json()
                .unwrap_or_else(|_| json!({"message": "unknown error"}));
            Ok((body, code))
        }
        Err(e) => Err(anyhow!("GitHub API request failed: {}", e)),
    }
}

// ─── Test utilities ──────────────────────────────────────────────────────────

/// Minimal mock server that serves one response. Used across all GitHub module tests.
#[cfg(test)]
pub fn mock_server(status: u16, body: &str) -> String {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = body.to_string();

    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
                len = body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });

    format!("http://127.0.0.1:{}", addr.port())
}

/// Standard config for GitHub module tests.
#[cfg(test)]
pub fn test_config(base_url: &str) -> std::collections::HashMap<String, String> {
    std::collections::HashMap::from([
        ("GITHUB_TOKEN".to_string(), "ghp_test".to_string()),
        ("GITHUB_OWNER".to_string(), "acme".to_string()),
        ("GITHUB_REPO".to_string(), "app".to_string()),
        ("GITHUB_API_URL".to_string(), base_url.to_string()),
    ])
}

/// Standard config with org field for org-level API tests.
#[cfg(test)]
pub fn test_config_with_org(base_url: &str) -> std::collections::HashMap<String, String> {
    let mut cfg = test_config(base_url);
    cfg.insert("GITHUB_ORG".to_string(), "acme-org".to_string());
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_get_success() {
        let srv = mock_server(200, r#"{"login":"octocat"}"#);
        let (body, status) = github_get("tok", &srv, "/user").unwrap();
        assert_eq!(status, 200);
        assert_eq!(body["login"], "octocat");
    }

    #[test]
    fn github_get_error_status() {
        let srv = mock_server(404, r#"{"message":"Not Found"}"#);
        let (body, status) = github_get("tok", &srv, "/missing").unwrap();
        assert_eq!(status, 404);
        assert_eq!(body["message"], "Not Found");
    }

    #[test]
    fn github_get_trims_trailing_slash() {
        let srv = mock_server(200, r#"{"ok":true}"#);
        let url_with_slash = format!("{}/", srv);
        let (_, status) = github_get("tok", &url_with_slash, "/test").unwrap();
        assert_eq!(status, 200);
    }
}
