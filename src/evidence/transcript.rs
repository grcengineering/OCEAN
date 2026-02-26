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
