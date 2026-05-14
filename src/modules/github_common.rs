// Shared GitHub API utilities for all GitHub observers and testers.
//
// Delegates to grc-controls-apis::github::GitHubClient under the hood.
// Preserves the legacy function signature for backward compatibility.

pub use grc_controls_apis::github::{DEFAULT_GITHUB_API, GITHUB_API_VERSION};

use anyhow::Result;
use grc_controls_apis::github::GitHubClient;
use grc_controls_apis::GitHubCredentials;
use secrecy::SecretString;
use serde_json::Value;

/// Performs an authenticated GET to the GitHub REST API v3.
/// `base_url` is `https://api.github.com` by default; tests override it.
pub fn github_get(token: &str, base_url: &str, path: &str) -> Result<(Value, u16)> {
    let creds = GitHubCredentials {
        token: SecretString::from(token.to_string()),
        org: None,
        owner: None,
        repo: None,
    };
    let client = GitHubClient::with_base_url(&creds, base_url);
    client.get(path)
}

// ─── Test utilities ──────────────────────────────────────────────────────────

/// Minimal mock server that serves one response. Used across all GitHub module tests.
#[cfg(test)]
pub fn mock_server(status: u16, body: &str) -> String {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener};
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
            let _ = stream.flush();
            // Graceful shutdown to avoid client-side partial-read races under
            // coverage instrumentation.
            let _ = stream.shutdown(Shutdown::Write);
            let mut drain = [0u8; 256];
            while matches!(stream.read(&mut drain), Ok(n) if n > 0) {}
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
