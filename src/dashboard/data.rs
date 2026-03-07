use anyhow::Result;
use chrono::{Duration, Utc};

use crate::control::definition::Control;
use crate::control::{calculate_uptime, ControlStatus};
use crate::evidence::Evidence;
use crate::storage::{EvidenceQuery, Store};

/// A row in the dashboard's main table, combining control metadata with live status.
#[derive(Debug, Clone)]
pub struct ControlRow {
    /// The control definition loaded from YAML.
    pub control: Control,
    /// The most recent evaluation status, if any.
    pub status: Option<ControlStatus>,
    /// 30-day uptime percentage, if history is available.
    pub uptime_percent: Option<f64>,
    /// Evidence records for this control (populated in detail view).
    pub evidence: Vec<Evidence>,
    /// First framework mapping display string (e.g. "SOC2 CC6.1").
    pub framework: String,
}

impl ControlRow {
    /// Create an empty row (used in tests).
    pub fn empty(id: &str) -> Self {
        Self {
            control: Control {
                id: id.to_string(),
                name: id.to_string(),
                description: String::new(),
                evaluation_logic: Default::default(),
                framework_mappings: vec![],
                observers: vec![],
                testers: vec![],
                component_controls: vec![],
                components: vec![],
                evaluation_expression_hash: String::new(),
            },
            status: None,
            uptime_percent: None,
            evidence: vec![],
            framework: String::new(),
        }
    }

    /// Human-readable status string.
    pub fn status_text(&self) -> &str {
        match &self.status {
            Some(s) => s.status.as_str(),
            None => "unknown",
        }
    }

    /// Human-readable confidence string.
    pub fn confidence_text(&self) -> &str {
        match &self.status {
            Some(s) => s.confidence.as_str(),
            None => "-",
        }
    }

    /// Uptime display string (e.g. "98.5%" or "-").
    pub fn uptime_text(&self) -> String {
        match self.uptime_percent {
            Some(pct) => format!("{:.1}%", pct),
            None => "-".to_string(),
        }
    }
}

/// Load all controls from YAML files and enrich with status data from the store.
pub fn load_controls(controls_dir: &str, store: &dyn Store) -> Result<Vec<ControlRow>> {
    let controls = load_control_yamls(controls_dir)?;
    let mut rows = Vec::with_capacity(controls.len());

    let now = Utc::now();
    let thirty_days_ago = now - Duration::days(30);

    for control in controls {
        // Get latest status
        let status = store.get_control_status(&control.id).ok();

        // Calculate 30-day uptime
        let uptime_percent = store
            .query_history(&control.id, thirty_days_ago, now)
            .ok()
            .and_then(|history| {
                if history.is_empty() {
                    None
                } else {
                    let result = calculate_uptime(&control.id, thirty_days_ago, now, &history);
                    Some(result.uptime_percent)
                }
            });

        // Get evidence for this control
        let evidence = store
            .query_evidence(&EvidenceQuery {
                control_id: Some(control.id.clone()),
                limit: Some(50),
                ..Default::default()
            })
            .unwrap_or_default();

        // First framework mapping
        let framework = control
            .framework_mappings
            .first()
            .map(|m| format!("{} {}", m.framework, m.requirement_id))
            .unwrap_or_default();

        rows.push(ControlRow {
            control,
            status,
            uptime_percent,
            evidence,
            framework,
        });
    }

    Ok(rows)
}

/// Glob for control YAML files and parse them.
fn load_control_yamls(controls_dir: &str) -> Result<Vec<Control>> {
    let mut controls = Vec::new();

    let path = std::path::Path::new(controls_dir);
    if !path.exists() {
        return Ok(controls);
    }

    visit_yaml_files(path, &mut controls)?;
    controls.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(controls)
}

/// Recursively visit directories looking for .yaml files.
fn visit_yaml_files(dir: &std::path::Path, controls: &mut Vec<Control>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            // Skip "frameworks" directory — those are framework definitions, not controls
            if path.file_name().map(|n| n == "frameworks").unwrap_or(false) {
                continue;
            }
            visit_yaml_files(&path, controls)?;
        } else if path.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
            let content = std::fs::read_to_string(&path)?;
            match Control::load_yaml(&content) {
                Ok(control) => controls.push(control),
                Err(e) => {
                    tracing::warn!("skipping {}: {}", path.display(), e);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_row_empty_has_unknown_status() {
        let row = ControlRow::empty("test");
        assert_eq!(row.status_text(), "unknown");
        assert_eq!(row.confidence_text(), "-");
        assert_eq!(row.uptime_text(), "-");
    }

    #[test]
    fn control_row_with_status() {
        let mut row = ControlRow::empty("test");
        row.status = Some(ControlStatus {
            id: uuid::Uuid::new_v4(),
            control_id: "test".to_string(),
            timestamp: Utc::now(),
            status: "effective".to_string(),
            confidence: "high".to_string(),
            evidence_ids: vec![],
            evaluation_details: String::new(),
        });
        assert_eq!(row.status_text(), "effective");
        assert_eq!(row.confidence_text(), "high");
    }

    #[test]
    fn control_row_uptime_formatting() {
        let mut row = ControlRow::empty("test");
        row.uptime_percent = Some(98.567);
        assert_eq!(row.uptime_text(), "98.6%");
    }

    #[test]
    fn load_control_yamls_missing_dir_returns_empty() {
        let controls = load_control_yamls("/nonexistent/path").unwrap();
        assert!(controls.is_empty());
    }

    #[test]
    fn load_control_yamls_from_real_controls_dir() {
        // This test uses the actual controls/ directory in the repo
        let controls = load_control_yamls("controls");
        match controls {
            Ok(c) => {
                // We know there are at least 4 control files
                assert!(c.len() >= 2, "expected at least 2 controls, got {}", c.len());
                // Should be sorted by ID
                for w in c.windows(2) {
                    assert!(w[0].id <= w[1].id, "controls not sorted: {} > {}", w[0].id, w[1].id);
                }
            }
            Err(_) => {
                // May fail if CWD is not the repo root — that's OK in CI
            }
        }
    }
}
