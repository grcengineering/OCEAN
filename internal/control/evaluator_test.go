package control

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
)

// helper to create a ControlStatus at a given time with a given status string.
func makeStatus(t time.Time, status, confidence string) ControlStatus {
	return ControlStatus{
		ID:          uuid.New(),
		ControlID:   "mock.test",
		Timestamp:   t,
		Status:      status,
		Confidence:  confidence,
		EvidenceIDs: []uuid.UUID{uuid.New()},
	}
}

func TestCalculateUptime_AllEffective(t *testing.T) {
	now := time.Date(2026, 2, 13, 0, 0, 0, 0, time.UTC)
	from := now.Add(-7 * 24 * time.Hour) // 7 days ago
	to := now
	interval := 24 * time.Hour

	// One effective status per day for 7 days.
	var statuses []ControlStatus
	for i := 0; i < 7; i++ {
		ts := from.Add(time.Duration(i)*24*time.Hour + 12*time.Hour) // mid-day
		statuses = append(statuses, makeStatus(ts, "effective", "high"))
	}

	result := CalculateUptime(statuses, from, to, interval)

	if result.ControlID != "mock.test" {
		t.Errorf("ControlID = %q, want %q", result.ControlID, "mock.test")
	}
	if result.TotalBuckets != 7 {
		t.Errorf("TotalBuckets = %d, want 7", result.TotalBuckets)
	}
	if result.EffectiveBuckets != 7 {
		t.Errorf("EffectiveBuckets = %d, want 7", result.EffectiveBuckets)
	}
	if result.IneffectiveBuckets != 0 {
		t.Errorf("IneffectiveBuckets = %d, want 0", result.IneffectiveBuckets)
	}
	if result.GapBuckets != 0 {
		t.Errorf("GapBuckets = %d, want 0", result.GapBuckets)
	}
	if result.UptimePercent != 100.0 {
		t.Errorf("UptimePercent = %f, want 100.0", result.UptimePercent)
	}
}

func TestCalculateUptime_WithGaps(t *testing.T) {
	now := time.Date(2026, 2, 13, 0, 0, 0, 0, time.UTC)
	from := now.Add(-7 * 24 * time.Hour)
	to := now
	interval := 24 * time.Hour

	// Only provide statuses for 5 of the 7 days (gaps on days 3 and 6).
	var statuses []ControlStatus
	for i := 0; i < 7; i++ {
		if i == 2 || i == 5 { // skip days 3 and 6 (0-indexed)
			continue
		}
		ts := from.Add(time.Duration(i)*24*time.Hour + 12*time.Hour)
		statuses = append(statuses, makeStatus(ts, "effective", "high"))
	}

	result := CalculateUptime(statuses, from, to, interval)

	if result.TotalBuckets != 7 {
		t.Errorf("TotalBuckets = %d, want 7", result.TotalBuckets)
	}
	if result.EffectiveBuckets != 5 {
		t.Errorf("EffectiveBuckets = %d, want 5", result.EffectiveBuckets)
	}
	if result.GapBuckets != 2 {
		t.Errorf("GapBuckets = %d, want 2", result.GapBuckets)
	}
	// Uptime = effective / (effective + ineffective) * 100 = 5/5 * 100 = 100
	if result.UptimePercent != 100.0 {
		t.Errorf("UptimePercent = %f, want 100.0", result.UptimePercent)
	}
}

func TestCalculateUptime_AllGaps(t *testing.T) {
	now := time.Date(2026, 2, 13, 0, 0, 0, 0, time.UTC)
	from := now.Add(-7 * 24 * time.Hour)
	to := now
	interval := 24 * time.Hour

	// No statuses at all.
	var statuses []ControlStatus

	result := CalculateUptime(statuses, from, to, interval)

	if result.TotalBuckets != 7 {
		t.Errorf("TotalBuckets = %d, want 7", result.TotalBuckets)
	}
	if result.GapBuckets != 7 {
		t.Errorf("GapBuckets = %d, want 7", result.GapBuckets)
	}
	if result.EffectiveBuckets != 0 {
		t.Errorf("EffectiveBuckets = %d, want 0", result.EffectiveBuckets)
	}
	if result.UptimePercent != 0.0 {
		t.Errorf("UptimePercent = %f, want 0.0", result.UptimePercent)
	}
}

func TestCalculateUptime_Mixed(t *testing.T) {
	now := time.Date(2026, 2, 13, 0, 0, 0, 0, time.UTC)
	from := now.Add(-5 * 24 * time.Hour)
	to := now
	interval := 24 * time.Hour

	// 5 days: 3 effective, 1 ineffective, 1 gap
	statuses := []ControlStatus{
		makeStatus(from.Add(12*time.Hour), "effective", "high"),             // day 1
		makeStatus(from.Add(24*time.Hour+12*time.Hour), "effective", "high"),  // day 2
		makeStatus(from.Add(2*24*time.Hour+12*time.Hour), "ineffective", "high"), // day 3
		// day 4: gap
		makeStatus(from.Add(4*24*time.Hour+12*time.Hour), "effective", "high"), // day 5
	}

	result := CalculateUptime(statuses, from, to, interval)

	if result.TotalBuckets != 5 {
		t.Errorf("TotalBuckets = %d, want 5", result.TotalBuckets)
	}
	if result.EffectiveBuckets != 3 {
		t.Errorf("EffectiveBuckets = %d, want 3", result.EffectiveBuckets)
	}
	if result.IneffectiveBuckets != 1 {
		t.Errorf("IneffectiveBuckets = %d, want 1", result.IneffectiveBuckets)
	}
	if result.GapBuckets != 1 {
		t.Errorf("GapBuckets = %d, want 1", result.GapBuckets)
	}
	// Uptime = 3 / (3+1) * 100 = 75.0
	if result.UptimePercent != 75.0 {
		t.Errorf("UptimePercent = %f, want 75.0", result.UptimePercent)
	}
}

func TestCalculateUptime_EmptyStatuses(t *testing.T) {
	now := time.Date(2026, 2, 13, 0, 0, 0, 0, time.UTC)
	from := now.Add(-3 * 24 * time.Hour)
	to := now
	interval := 24 * time.Hour

	result := CalculateUptime(nil, from, to, interval)

	if result.TotalBuckets != 3 {
		t.Errorf("TotalBuckets = %d, want 3", result.TotalBuckets)
	}
	if result.GapBuckets != 3 {
		t.Errorf("GapBuckets = %d, want 3", result.GapBuckets)
	}
	if result.UptimePercent != 0.0 {
		t.Errorf("UptimePercent = %f, want 0.0", result.UptimePercent)
	}
}

func TestCalculateUptime_EdgeCaseFromAfterTo(t *testing.T) {
	now := time.Date(2026, 2, 13, 0, 0, 0, 0, time.UTC)
	from := now
	to := now.Add(-7 * 24 * time.Hour) // from > to
	interval := 24 * time.Hour

	result := CalculateUptime(nil, from, to, interval)

	if result.TotalBuckets != 0 {
		t.Errorf("TotalBuckets = %d, want 0", result.TotalBuckets)
	}
	if result.UptimePercent != 0.0 {
		t.Errorf("UptimePercent = %f, want 0.0", result.UptimePercent)
	}
}

func TestCalculateUptime_EdgeCaseZeroInterval(t *testing.T) {
	now := time.Date(2026, 2, 13, 0, 0, 0, 0, time.UTC)
	from := now.Add(-7 * 24 * time.Hour)
	to := now

	result := CalculateUptime(nil, from, to, 0)

	if result.TotalBuckets != 0 {
		t.Errorf("TotalBuckets = %d, want 0 for zero interval", result.TotalBuckets)
	}
	if result.UptimePercent != 0.0 {
		t.Errorf("UptimePercent = %f, want 0.0 for zero interval", result.UptimePercent)
	}
}

func TestCalculateUptime_MultipleStatusesPerBucket(t *testing.T) {
	// When multiple statuses exist in a bucket, the most recent one wins.
	now := time.Date(2026, 2, 13, 0, 0, 0, 0, time.UTC)
	from := now.Add(-24 * time.Hour)
	to := now
	interval := 24 * time.Hour

	statuses := []ControlStatus{
		makeStatus(from.Add(6*time.Hour), "ineffective", "high"),  // earlier in bucket
		makeStatus(from.Add(18*time.Hour), "effective", "high"),   // later in bucket (wins)
	}

	result := CalculateUptime(statuses, from, to, interval)

	if result.TotalBuckets != 1 {
		t.Errorf("TotalBuckets = %d, want 1", result.TotalBuckets)
	}
	if result.EffectiveBuckets != 1 {
		t.Errorf("EffectiveBuckets = %d, want 1 (most recent status in bucket)", result.EffectiveBuckets)
	}
	if result.IneffectiveBuckets != 0 {
		t.Errorf("IneffectiveBuckets = %d, want 0", result.IneffectiveBuckets)
	}
}

// --- EvaluateControl and DetermineConfidence tests ---

// makeEvidence creates a test evidence record with the given parameters.
func makeEvidence(statusID evidence.StatusID, conf evidence.ConfidenceLevel, age time.Duration) evidence.Evidence {
	return evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "mock.mfa_enforcement",
		ClassUID:        1001,
		CategoryUID:     1,
		ActivityID:      1,
		Time:            time.Now().UTC().Add(-age),
		ConfidenceLevel: conf,
		StatusID:        statusID,
		Status:          "test evidence",
	}
}

func TestEvaluateControl_AllEffective(t *testing.T) {
	ctrl := &Control{ID: "mock.mfa_enforcement", Name: "MFA Enforcement"}

	evidences := []evidence.Evidence{
		makeEvidence(evidence.StatusEffective, evidence.PassiveObservation, 0),
		makeEvidence(evidence.StatusEffective, evidence.ActiveVerification, 0),
	}

	cs, err := EvaluateControl(ctrl, evidences)
	if err != nil {
		t.Fatalf("EvaluateControl error: %v", err)
	}

	if cs.Status != "effective" {
		t.Errorf("Status = %q, want %q", cs.Status, "effective")
	}
	if cs.ControlID != "mock.mfa_enforcement" {
		t.Errorf("ControlID = %q, want %q", cs.ControlID, "mock.mfa_enforcement")
	}
	if cs.Confidence != "high" {
		t.Errorf("Confidence = %q, want %q", cs.Confidence, "high")
	}
	if len(cs.EvidenceIDs) != 2 {
		t.Errorf("EvidenceIDs len = %d, want 2", len(cs.EvidenceIDs))
	}
}

func TestEvaluateControl_HasIneffective(t *testing.T) {
	ctrl := &Control{ID: "mock.mfa_enforcement", Name: "MFA Enforcement"}

	evidences := []evidence.Evidence{
		makeEvidence(evidence.StatusEffective, evidence.PassiveObservation, 0),
		makeEvidence(evidence.StatusIneffective, evidence.PassiveObservation, 0),
	}

	cs, err := EvaluateControl(ctrl, evidences)
	if err != nil {
		t.Fatalf("EvaluateControl error: %v", err)
	}

	if cs.Status != "ineffective" {
		t.Errorf("Status = %q, want %q", cs.Status, "ineffective")
	}
}

func TestEvaluateControl_NoEvidence(t *testing.T) {
	ctrl := &Control{ID: "mock.mfa_enforcement", Name: "MFA Enforcement"}

	cs, err := EvaluateControl(ctrl, nil)
	if err != nil {
		t.Fatalf("EvaluateControl error: %v", err)
	}

	if cs.Status != "unknown" {
		t.Errorf("Status = %q, want %q", cs.Status, "unknown")
	}
	if cs.Confidence != "low" {
		t.Errorf("Confidence = %q, want %q", cs.Confidence, "low")
	}
}

func TestEvaluateControl_Discrepancy(t *testing.T) {
	ctrl := &Control{ID: "mock.mfa_enforcement", Name: "MFA Enforcement"}

	// Passive says effective, active says ineffective -- active wins.
	evidences := []evidence.Evidence{
		makeEvidence(evidence.StatusEffective, evidence.PassiveObservation, 0),
		makeEvidence(evidence.StatusIneffective, evidence.ActiveVerification, 0),
	}

	cs, err := EvaluateControl(ctrl, evidences)
	if err != nil {
		t.Fatalf("EvaluateControl error: %v", err)
	}

	if cs.Status != "ineffective" {
		t.Errorf("Status = %q, want %q (active takes precedence)", cs.Status, "ineffective")
	}

	// Should note the discrepancy in evaluation details.
	if !strings.Contains(cs.EvaluationDetails, "discrepancy") {
		t.Errorf("EvaluationDetails should mention discrepancy, got: %s", cs.EvaluationDetails)
	}
}

func TestEvaluateControl_Partial(t *testing.T) {
	ctrl := &Control{ID: "mock.test", Name: "Test Control"}

	// Mix of effective and unknown -- should be "partial".
	evidences := []evidence.Evidence{
		makeEvidence(evidence.StatusEffective, evidence.PassiveObservation, 0),
		makeEvidence(evidence.StatusUnknown, evidence.PassiveObservation, 0),
	}

	cs, err := EvaluateControl(ctrl, evidences)
	if err != nil {
		t.Fatalf("EvaluateControl error: %v", err)
	}

	if cs.Status != "partial" {
		t.Errorf("Status = %q, want %q", cs.Status, "partial")
	}
}

func TestDetermineConfidence_Both(t *testing.T) {
	// Both passive and active evidence present and they agree.
	evidences := []evidence.Evidence{
		makeEvidence(evidence.StatusEffective, evidence.PassiveObservation, 0),
		makeEvidence(evidence.StatusEffective, evidence.ActiveVerification, 0),
	}

	conf := DetermineConfidence(evidences)
	if conf != "high" {
		t.Errorf("Confidence = %q, want %q", conf, "high")
	}
}

func TestDetermineConfidence_PassiveOnly(t *testing.T) {
	evidences := []evidence.Evidence{
		makeEvidence(evidence.StatusEffective, evidence.PassiveObservation, 0),
	}

	conf := DetermineConfidence(evidences)
	if conf != "medium" {
		t.Errorf("Confidence = %q, want %q", conf, "medium")
	}
}

func TestDetermineConfidence_ActiveOnly(t *testing.T) {
	evidences := []evidence.Evidence{
		makeEvidence(evidence.StatusEffective, evidence.ActiveVerification, 0),
	}

	conf := DetermineConfidence(evidences)
	if conf != "medium" {
		t.Errorf("Confidence = %q, want %q", conf, "medium")
	}
}

func TestDetermineConfidence_StaleEvidence(t *testing.T) {
	// Evidence older than 24h should result in low confidence.
	evidences := []evidence.Evidence{
		makeEvidence(evidence.StatusEffective, evidence.PassiveObservation, 25*time.Hour),
		makeEvidence(evidence.StatusEffective, evidence.ActiveVerification, 25*time.Hour),
	}

	conf := DetermineConfidence(evidences)
	if conf != "low" {
		t.Errorf("Confidence = %q, want %q (stale evidence)", conf, "low")
	}
}

func TestDetermineConfidence_Disagreement(t *testing.T) {
	// Passive effective + active ineffective = low confidence due to disagreement.
	evidences := []evidence.Evidence{
		makeEvidence(evidence.StatusEffective, evidence.PassiveObservation, 0),
		makeEvidence(evidence.StatusIneffective, evidence.ActiveVerification, 0),
	}

	conf := DetermineConfidence(evidences)
	if conf != "low" {
		t.Errorf("Confidence = %q, want %q (disagreement)", conf, "low")
	}
}

func TestDetermineConfidence_Empty(t *testing.T) {
	conf := DetermineConfidence(nil)
	if conf != "low" {
		t.Errorf("Confidence = %q, want %q", conf, "low")
	}
}

// --- CELEvaluateControl tests (T100) ---

func TestCELEvaluateControl_AllEffective(t *testing.T) {
	ctrl := &Control{
		ID:   "mock.mfa_enforcement",
		Name: "MFA Enforcement",
		EvaluationLogic: EvaluationLogic{
			CELExpression: "status_counts.ineffective == 0 && status_counts.effective > 0",
		},
	}

	evidences := []evidence.Evidence{
		makeEvidence(evidence.StatusEffective, evidence.PassiveObservation, 0),
		makeEvidence(evidence.StatusEffective, evidence.ActiveVerification, 0),
	}

	cs, err := CELEvaluateControl(ctrl, evidences, "")
	if err != nil {
		t.Fatalf("CELEvaluateControl error: %v", err)
	}

	if cs.Status != "effective" {
		t.Errorf("Status = %q, want %q", cs.Status, "effective")
	}
	if cs.ControlID != "mock.mfa_enforcement" {
		t.Errorf("ControlID = %q, want %q", cs.ControlID, "mock.mfa_enforcement")
	}
	if !strings.Contains(cs.EvaluationDetails, "sha256:") {
		t.Errorf("EvaluationDetails should contain expression hash, got: %s", cs.EvaluationDetails)
	}
}

func TestCELEvaluateControl_HasIneffective(t *testing.T) {
	ctrl := &Control{
		ID:   "mock.mfa_enforcement",
		Name: "MFA Enforcement",
		EvaluationLogic: EvaluationLogic{
			CELExpression: "status_counts.ineffective == 0 && status_counts.effective > 0",
		},
	}

	evidences := []evidence.Evidence{
		makeEvidence(evidence.StatusEffective, evidence.PassiveObservation, 0),
		makeEvidence(evidence.StatusIneffective, evidence.PassiveObservation, 0),
	}

	cs, err := CELEvaluateControl(ctrl, evidences, "")
	if err != nil {
		t.Fatalf("CELEvaluateControl error: %v", err)
	}

	if cs.Status != "ineffective" {
		t.Errorf("Status = %q, want %q", cs.Status, "ineffective")
	}
}

func TestCELEvaluateControl_NoEvidence(t *testing.T) {
	ctrl := &Control{
		ID:   "mock.mfa_enforcement",
		Name: "MFA Enforcement",
		EvaluationLogic: EvaluationLogic{
			CELExpression: "status_counts.effective > 0",
		},
	}

	cs, err := CELEvaluateControl(ctrl, nil, "")
	if err != nil {
		t.Fatalf("CELEvaluateControl error: %v", err)
	}

	if cs.Status != "unknown" {
		t.Errorf("Status = %q, want %q", cs.Status, "unknown")
	}
	if cs.Confidence != "low" {
		t.Errorf("Confidence = %q, want %q", cs.Confidence, "low")
	}
}

func TestCELEvaluateControl_WithPreset(t *testing.T) {
	ctrl := &Control{
		ID:   "mock.mfa_enforcement",
		Name: "MFA Enforcement",
		EvaluationLogic: EvaluationLogic{
			Preset: "all_effective",
		},
	}

	evidences := []evidence.Evidence{
		makeEvidence(evidence.StatusEffective, evidence.PassiveObservation, 0),
		makeEvidence(evidence.StatusEffective, evidence.ActiveVerification, 0),
	}

	cs, err := CELEvaluateControl(ctrl, evidences, "")
	if err != nil {
		t.Fatalf("CELEvaluateControl error: %v", err)
	}

	if cs.Status != "effective" {
		t.Errorf("Status = %q, want %q", cs.Status, "effective")
	}
}

func TestCELEvaluateControl_CELOverride(t *testing.T) {
	ctrl := &Control{
		ID:   "mock.test",
		Name: "Test Control",
		EvaluationLogic: EvaluationLogic{
			CELExpression: "status_counts.effective > 0",
		},
	}

	evidences := []evidence.Evidence{
		makeEvidence(evidence.StatusEffective, evidence.PassiveObservation, 0),
		makeEvidence(evidence.StatusIneffective, evidence.PassiveObservation, 0),
	}

	// The control's own expression would say "effective" (any_effective).
	// Override with all_effective which should say "ineffective".
	cs, err := CELEvaluateControl(ctrl, evidences, "status_counts.ineffective == 0 && status_counts.effective > 0")
	if err != nil {
		t.Fatalf("CELEvaluateControl error: %v", err)
	}

	if cs.Status != "ineffective" {
		t.Errorf("Status = %q, want %q (override should apply)", cs.Status, "ineffective")
	}
}

func TestCELEvaluateControl_InvalidExpression(t *testing.T) {
	ctrl := &Control{
		ID:   "mock.test",
		Name: "Test Control",
		EvaluationLogic: EvaluationLogic{
			CELExpression: "invalid syntax ==",
		},
	}

	evidences := []evidence.Evidence{
		makeEvidence(evidence.StatusEffective, evidence.PassiveObservation, 0),
	}

	_, err := CELEvaluateControl(ctrl, evidences, "")
	if err == nil {
		t.Fatal("CELEvaluateControl should error on invalid CEL expression")
	}
}

func TestCELEvaluateControl_NoExpressionOrPreset(t *testing.T) {
	ctrl := &Control{
		ID:   "mock.test",
		Name: "Test Control",
		EvaluationLogic: EvaluationLogic{},
	}

	evidences := []evidence.Evidence{
		makeEvidence(evidence.StatusEffective, evidence.PassiveObservation, 0),
	}

	_, err := CELEvaluateControl(ctrl, evidences, "")
	if err == nil {
		t.Fatal("CELEvaluateControl should error when no expression or preset is provided")
	}
}

func TestCELEvaluateControl_SetsExpressionHash(t *testing.T) {
	ctrl := &Control{
		ID:   "mock.test",
		Name: "Test Control",
		EvaluationLogic: EvaluationLogic{
			CELExpression: "status_counts.effective > 0",
		},
	}

	evidences := []evidence.Evidence{
		makeEvidence(evidence.StatusEffective, evidence.PassiveObservation, 0),
	}

	_, err := CELEvaluateControl(ctrl, evidences, "")
	if err != nil {
		t.Fatalf("CELEvaluateControl error: %v", err)
	}

	if ctrl.EvaluationExpressionHash == "" {
		t.Error("EvaluationExpressionHash should be set after evaluation")
	}
	if !strings.HasPrefix(ctrl.EvaluationExpressionHash, "sha256:") {
		t.Errorf("EvaluationExpressionHash = %q, want sha256: prefix", ctrl.EvaluationExpressionHash)
	}
}

func TestCELEvaluateControl_ActiveVerifiedPreset(t *testing.T) {
	ctrl := &Control{
		ID:   "mock.test",
		Name: "Test Control",
		EvaluationLogic: EvaluationLogic{
			Preset: "active_verified",
		},
	}

	// Only passive evidence -- should be ineffective (no active present).
	passiveOnly := []evidence.Evidence{
		makeEvidence(evidence.StatusEffective, evidence.PassiveObservation, 0),
	}

	cs, err := CELEvaluateControl(ctrl, passiveOnly, "")
	if err != nil {
		t.Fatalf("CELEvaluateControl error: %v", err)
	}

	if cs.Status != "ineffective" {
		t.Errorf("Status = %q, want %q (no active verification)", cs.Status, "ineffective")
	}
}
