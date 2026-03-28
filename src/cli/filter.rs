// Check filtering — tag, severity, and profile filters for CLI commands.

use ocean::check::definition::CheckDefinition;

/// Filter criteria for check selection.
#[derive(Debug, Default)]
pub struct CheckFilter {
    /// Include only checks with at least one of these tags.
    pub tags: Vec<String>,
    /// Include only checks with one of these severity levels.
    pub severities: Vec<String>,
    /// Include only checks at this profile tier or below.
    pub profile: Option<String>,
}

impl CheckFilter {
    /// Returns true if no filters are set.
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty() && self.severities.is_empty() && self.profile.is_none()
    }

    /// Returns true if the check matches all active filters.
    pub fn matches(&self, def: &CheckDefinition) -> bool {
        self.matches_tags(def) && self.matches_severity(def) && self.matches_profile(def)
    }

    fn matches_tags(&self, def: &CheckDefinition) -> bool {
        if self.tags.is_empty() {
            return true;
        }
        def.tags.iter().any(|t| self.tags.contains(t))
    }

    fn matches_severity(&self, def: &CheckDefinition) -> bool {
        if self.severities.is_empty() {
            return true;
        }
        let sev = effective_severity(def);
        self.severities.iter().any(|s| s.eq_ignore_ascii_case(&sev))
    }

    fn matches_profile(&self, def: &CheckDefinition) -> bool {
        let target = match &self.profile {
            Some(p) => p,
            None => return true,
        };
        if def.profile.is_empty() {
            // Checks without a profile are included (no tier restriction).
            return true;
        }
        profile_rank(&def.profile) <= profile_rank(target)
    }
}

/// Parse a comma-separated string into a filter field.
pub fn parse_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Rank profiles: L1 < L2 < L3.
fn profile_rank(p: &str) -> u8 {
    match p.to_uppercase().as_str() {
        "L1" => 1,
        "L2" => 2,
        "L3" => 3,
        _ => 0,
    }
}

/// Determine effective severity from assertion or top-level field.
fn effective_severity(def: &CheckDefinition) -> String {
    if let Some(a) = def.assertions.first() {
        if !a.severity.is_empty() {
            return a.severity.clone();
        }
    }
    if !def.severity.is_empty() {
        return def.severity.clone();
    }
    "medium".to_string()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_def(id: &str, tags: &[&str], severity: &str, profile: &str) -> CheckDefinition {
        let tag_str = tags
            .iter()
            .map(|t| format!("\"{}\"", t))
            .collect::<Vec<_>>()
            .join(", ");
        let yaml = format!(
            r#"
id: {id}
name: Test Check
source: github
severity: {severity}
profile: {profile}
tags: [{tag_str}]
"#
        );
        serde_yaml::from_str(&yaml).unwrap()
    }

    #[test]
    fn empty_filter_matches_everything() {
        let f = CheckFilter::default();
        assert!(f.is_empty());
        assert!(f.matches(&make_def("T-1", &["mfa"], "critical", "L1")));
    }

    #[test]
    fn tag_filter_includes_matching() {
        let f = CheckFilter {
            tags: vec!["mfa".into()],
            ..Default::default()
        };
        assert!(f.matches(&make_def("T-1", &["mfa", "identity"], "medium", "L1")));
        assert!(!f.matches(&make_def("T-2", &["actions"], "medium", "L1")));
    }

    #[test]
    fn severity_filter_includes_matching() {
        let f = CheckFilter {
            severities: vec!["critical".into(), "high".into()],
            ..Default::default()
        };
        assert!(f.matches(&make_def("T-1", &[], "critical", "")));
        assert!(f.matches(&make_def("T-2", &[], "high", "")));
        assert!(!f.matches(&make_def("T-3", &[], "medium", "")));
    }

    #[test]
    fn profile_filter_includes_tier_and_below() {
        let f = CheckFilter {
            profile: Some("L2".into()),
            ..Default::default()
        };
        assert!(f.matches(&make_def("T-1", &[], "medium", "L1")));
        assert!(f.matches(&make_def("T-2", &[], "medium", "L2")));
        assert!(!f.matches(&make_def("T-3", &[], "medium", "L3")));
    }

    #[test]
    fn profile_filter_includes_unset_profile() {
        let f = CheckFilter {
            profile: Some("L1".into()),
            ..Default::default()
        };
        assert!(f.matches(&make_def("T-1", &[], "medium", "")));
    }

    #[test]
    fn combined_filters_are_and() {
        let f = CheckFilter {
            tags: vec!["mfa".into()],
            severities: vec!["critical".into()],
            profile: Some("L1".into()),
        };
        // All match
        assert!(f.matches(&make_def("T-1", &["mfa"], "critical", "L1")));
        // Tag mismatch
        assert!(!f.matches(&make_def("T-2", &["actions"], "critical", "L1")));
        // Severity mismatch
        assert!(!f.matches(&make_def("T-3", &["mfa"], "low", "L1")));
        // Profile mismatch
        assert!(!f.matches(&make_def("T-4", &["mfa"], "critical", "L3")));
    }

    #[test]
    fn parse_csv_splits_and_lowercases() {
        assert_eq!(parse_csv("MFA, Identity"), vec!["mfa", "identity"]);
        assert_eq!(parse_csv("critical,HIGH"), vec!["critical", "high"]);
        assert_eq!(parse_csv(""), Vec::<String>::new());
    }
}
