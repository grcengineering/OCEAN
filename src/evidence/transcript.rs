// Re-export transcript types from the shared crate.
pub use grc_controls_models::transcript::{
    TestTranscript, TranscriptAction, TranscriptCleanup, TranscriptObservation, TranscriptRecorder,
};

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
        rec.record_action(
            "send_request",
            Some(serde_json::json!({"url": "http://example.com"})),
        );
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
        assert!(t.actions_attempted[1].parameters.is_null()); // None → Null

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
