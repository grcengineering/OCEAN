use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Full audit trail of an active verification test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestTranscript {
    pub actions_attempted: Vec<TranscriptAction>,
    pub observations: Vec<TranscriptObservation>,
    pub cleanup_actions: Vec<TranscriptCleanup>,
}

/// A single action attempted during an active test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptAction {
    pub action: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub parameters: Value,
}

/// What was observed during an active test, and whether it matched expectations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptObservation {
    pub observation: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub expected: bool,
}

/// A cleanup action taken after an active test to restore environment state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptCleanup {
    pub action: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub success: bool,
}

// ---------------------------------------------------------------------------
// TranscriptRecorder
// ---------------------------------------------------------------------------

/// Builds a TestTranscript incrementally during test execution.
#[derive(Debug, Default)]
pub struct TranscriptRecorder {
    actions: Vec<TranscriptAction>,
    observations: Vec<TranscriptObservation>,
    cleanups: Vec<TranscriptCleanup>,
}

impl TranscriptRecorder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_action(&mut self, action: impl Into<String>, params: Option<Value>) {
        self.actions.push(TranscriptAction {
            action: action.into(),
            timestamp: Utc::now(),
            parameters: params.unwrap_or(Value::Null),
        });
    }

    pub fn record_observation(&mut self, observation: impl Into<String>, expected: bool) {
        self.observations.push(TranscriptObservation {
            observation: observation.into(),
            timestamp: Utc::now(),
            expected,
        });
    }

    pub fn record_cleanup(&mut self, action: impl Into<String>, success: bool) {
        self.cleanups.push(TranscriptCleanup {
            action: action.into(),
            timestamp: Utc::now(),
            success,
        });
    }

    /// Consumes the recorder and returns the completed TestTranscript.
    pub fn finalize(self) -> TestTranscript {
        TestTranscript {
            actions_attempted: self.actions,
            observations: self.observations,
            cleanup_actions: self.cleanups,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorder_empty_finalize() {
        let rec = TranscriptRecorder::new();
        let t = rec.finalize();
        assert!(t.actions_attempted.is_empty());
        assert!(t.observations.is_empty());
        assert!(t.cleanup_actions.is_empty());
    }

    #[test]
    fn recorder_records_all_types() {
        let mut rec = TranscriptRecorder::new();
        rec.record_action("send_request", Some(serde_json::json!({"url": "http://example.com"})));
        rec.record_action("second_action", None);
        rec.record_observation("response_blocked", true);
        rec.record_observation("alert_fired", false);
        rec.record_cleanup("restore_rule", true);
        rec.record_cleanup("delete_temp", false);

        let t = rec.finalize();
        assert_eq!(t.actions_attempted.len(), 2);
        assert_eq!(t.observations.len(), 2);
        assert_eq!(t.cleanup_actions.len(), 2);

        assert_eq!(t.actions_attempted[0].action, "send_request");
        assert!(!t.actions_attempted[0].parameters.is_null()); // has params
        assert!(t.actions_attempted[1].parameters.is_null());  // None → Null

        assert!(t.observations[0].expected);
        assert!(!t.observations[1].expected);

        assert!(t.cleanup_actions[0].success);
        assert!(!t.cleanup_actions[1].success);
    }

    #[test]
    fn transcript_serde_round_trip() {
        let mut rec = TranscriptRecorder::new();
        rec.record_action("test_action", None);
        rec.record_observation("passed", true);
        rec.record_cleanup("restored", true);
        let t = rec.finalize();
        let json = serde_json::to_string(&t).unwrap();
        let decoded: TestTranscript = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.actions_attempted.len(), 1);
        assert_eq!(decoded.observations.len(), 1);
        assert_eq!(decoded.cleanup_actions.len(), 1);
    }

    #[test]
    fn recorder_default_is_empty() {
        let rec = TranscriptRecorder::default();
        let t = rec.finalize();
        assert!(t.actions_attempted.is_empty());
    }
}
