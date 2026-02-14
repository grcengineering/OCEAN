package cli

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/control"
	"github.com/grcengineering/ocean/internal/evidence"
)

// --- T159: Markdown report tests ---

func TestGenerateMarkdownReport_BasicStructure(t *testing.T) {
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC)

	evs := []evidence.Evidence{
		makeEvidence("ctrl-1", now, evidence.StatusEffective, "effective", evidence.PassiveObservation, "okta-mfa"),
	}

	statuses := []control.ControlStatus{
		makeControlStatus("ctrl-1", now, "effective", "high"),
	}

	opts := reportOptions{
		format: "markdown",
		from:   from,
		to:     to,
	}

	var buf bytes.Buffer
	err := generateMarkdownReport(&buf, evs, statuses, opts)
	if err != nil {
		t.Fatalf("generateMarkdownReport returned error: %v", err)
	}

	output := buf.String()

	// Must contain report header
	if !strings.Contains(output, "OCEAN Compliance Report") {
		t.Error("markdown report missing header")
	}

	// Must contain period
	if !strings.Contains(output, "2026-01-01") {
		t.Error("markdown report missing period start date")
	}

	// Must contain control ID
	if !strings.Contains(output, "ctrl-1") {
		t.Error("markdown report missing control ID")
	}
}

func TestGenerateMarkdownReport_ControlStatusSummary(t *testing.T) {
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC)

	evs := []evidence.Evidence{
		makeEvidence("ctrl-1", now, evidence.StatusEffective, "effective", evidence.PassiveObservation, "okta-mfa"),
		makeEvidence("ctrl-1", now.Add(-time.Hour), evidence.StatusEffective, "effective", evidence.ActiveVerification, "okta-mfa-test"),
	}

	statuses := []control.ControlStatus{
		makeControlStatus("ctrl-1", now, "effective", "high"),
	}

	opts := reportOptions{
		format: "markdown",
		from:   from,
		to:     to,
	}

	var buf bytes.Buffer
	err := generateMarkdownReport(&buf, evs, statuses, opts)
	if err != nil {
		t.Fatalf("generateMarkdownReport returned error: %v", err)
	}

	output := buf.String()

	// Must show status
	if !strings.Contains(output, "effective") {
		t.Error("markdown report missing control status")
	}

	// Must show confidence
	if !strings.Contains(output, "high") {
		t.Error("markdown report missing confidence level")
	}
}

func TestGenerateMarkdownReport_PerControlEvidenceBreakdown(t *testing.T) {
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC)

	evs := []evidence.Evidence{
		makeEvidence("ctrl-1", now, evidence.StatusEffective, "effective", evidence.PassiveObservation, "okta-mfa"),
		makeEvidence("ctrl-1", now.Add(-time.Hour), evidence.StatusEffective, "effective", evidence.ActiveVerification, "okta-mfa-test"),
	}

	statuses := []control.ControlStatus{
		makeControlStatus("ctrl-1", now, "effective", "high"),
	}

	opts := reportOptions{
		format: "markdown",
		from:   from,
		to:     to,
	}

	var buf bytes.Buffer
	err := generateMarkdownReport(&buf, evs, statuses, opts)
	if err != nil {
		t.Fatalf("generateMarkdownReport returned error: %v", err)
	}

	output := buf.String()

	// Must distinguish passive and active evidence
	if !strings.Contains(output, "passive_observation") {
		t.Error("markdown report missing passive evidence indication")
	}
	if !strings.Contains(output, "active_verification") {
		t.Error("markdown report missing active evidence indication")
	}

	// Must show module source
	if !strings.Contains(output, "okta-mfa") {
		t.Error("markdown report missing module source")
	}
}

// --- T160: CSV report tests ---

func TestGenerateCSVReport_Columns(t *testing.T) {
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)

	evs := []evidence.Evidence{
		makeEvidence("ctrl-1", now, evidence.StatusEffective, "effective", evidence.PassiveObservation, "okta-mfa"),
	}

	var buf bytes.Buffer
	err := generateCSVReport(&buf, evs, nil, reportOptions{})
	if err != nil {
		t.Fatalf("generateCSVReport returned error: %v", err)
	}

	reader := csv.NewReader(strings.NewReader(buf.String()))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("CSV parse error: %v", err)
	}

	if len(records) < 2 {
		t.Fatalf("expected at least 2 rows (header + data), got %d", len(records))
	}

	header := records[0]
	expectedCols := []string{"control_id", "timestamp", "status", "confidence", "source", "module", "confidence_level", "has_attestation"}
	if len(header) != len(expectedCols) {
		t.Fatalf("expected %d columns, got %d: %v", len(expectedCols), len(header), header)
	}

	for i, col := range expectedCols {
		if header[i] != col {
			t.Errorf("column %d: expected %q, got %q", i, col, header[i])
		}
	}
}

func TestGenerateCSVReport_DataRow(t *testing.T) {
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)

	evs := []evidence.Evidence{
		makeEvidence("ctrl-1", now, evidence.StatusEffective, "effective", evidence.PassiveObservation, "okta-mfa"),
	}

	var buf bytes.Buffer
	err := generateCSVReport(&buf, evs, nil, reportOptions{})
	if err != nil {
		t.Fatalf("generateCSVReport returned error: %v", err)
	}

	reader := csv.NewReader(strings.NewReader(buf.String()))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("CSV parse error: %v", err)
	}

	row := records[1]
	if row[0] != "ctrl-1" {
		t.Errorf("control_id: expected %q, got %q", "ctrl-1", row[0])
	}
	if row[2] != "effective" {
		t.Errorf("status: expected %q, got %q", "effective", row[2])
	}
	if row[6] != "passive_observation" {
		t.Errorf("confidence_level: expected %q, got %q", "passive_observation", row[6])
	}
}

func TestGenerateCSVReport_MultipleRows(t *testing.T) {
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)

	evs := []evidence.Evidence{
		makeEvidence("ctrl-1", now, evidence.StatusEffective, "effective", evidence.PassiveObservation, "okta-mfa"),
		makeEvidence("ctrl-2", now, evidence.StatusIneffective, "ineffective", evidence.ActiveVerification, "aws-test"),
	}

	var buf bytes.Buffer
	err := generateCSVReport(&buf, evs, nil, reportOptions{})
	if err != nil {
		t.Fatalf("generateCSVReport returned error: %v", err)
	}

	reader := csv.NewReader(strings.NewReader(buf.String()))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("CSV parse error: %v", err)
	}

	if len(records) != 3 {
		t.Fatalf("expected 3 rows (header + 2 data), got %d", len(records))
	}
}

// --- T161: Provenance verification tests ---

func TestProvStatusString(t *testing.T) {
	tests := []struct {
		name     string
		hasAttn  bool
		verified *bool
		want     string
	}{
		{"no attestation", false, nil, "Unverified"},
		{"verified true", true, boolPtr(true), "Verified"},
		{"verified false", true, boolPtr(false), "Failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := provStatusString(tt.hasAttn, tt.verified)
			if got != tt.want {
				t.Errorf("provStatusString(%v, %v) = %q, want %q", tt.hasAttn, tt.verified, got, tt.want)
			}
		})
	}
}

// --- T162: Active test transcript summaries ---

func TestFormatTranscriptSummary(t *testing.T) {
	transcript := &evidence.TestTranscript{
		ActionsAttempted: []evidence.TranscriptAction{
			{Action: "Attempt login without MFA"},
			{Action: "Check MFA enforcement"},
		},
		Observations: []evidence.TranscriptObservation{
			{Observation: "Login blocked by MFA", Expected: true},
		},
		CleanupActions: []evidence.TranscriptCleanup{
			{Action: "Remove test user", Success: true},
		},
	}

	result := formatTranscriptSummary(transcript)

	if !strings.Contains(result, "Attempt login without MFA") {
		t.Error("transcript summary missing action")
	}
	if !strings.Contains(result, "Login blocked by MFA") {
		t.Error("transcript summary missing observation")
	}
	if !strings.Contains(result, "Remove test user") {
		t.Error("transcript summary missing cleanup action")
	}
}

func TestFormatTranscriptSummary_Nil(t *testing.T) {
	result := formatTranscriptSummary(nil)
	if result != "" {
		t.Errorf("expected empty string for nil transcript, got %q", result)
	}
}

// --- T163: Data quality disclaimers ---

func TestGenerateDataQualityDisclaimer_HighGaps(t *testing.T) {
	// >10% gaps should trigger disclaimer
	uptime := control.UptimeResult{
		TotalBuckets:       100,
		EffectiveBuckets:   70,
		IneffectiveBuckets: 5,
		GapBuckets:         25,
		UptimePercent:      93.33,
	}

	disclaimer := generateDataQualityDisclaimer(uptime)

	if disclaimer == "" {
		t.Fatal("expected non-empty disclaimer for high gaps")
	}
	if !strings.Contains(disclaimer, "WARNING") {
		t.Error("disclaimer missing WARNING marker")
	}
	if !strings.Contains(disclaimer, "25.0%") {
		t.Errorf("disclaimer missing gap percentage, got: %s", disclaimer)
	}
}

func TestGenerateDataQualityDisclaimer_LowGaps(t *testing.T) {
	// <=10% gaps should not trigger disclaimer
	uptime := control.UptimeResult{
		TotalBuckets:       100,
		EffectiveBuckets:   85,
		IneffectiveBuckets: 10,
		GapBuckets:         5,
		UptimePercent:      89.47,
	}

	disclaimer := generateDataQualityDisclaimer(uptime)

	if disclaimer != "" {
		t.Errorf("expected empty disclaimer for low gaps, got %q", disclaimer)
	}
}

func TestGenerateDataQualityDisclaimer_NoData(t *testing.T) {
	// No data at all
	uptime := control.UptimeResult{
		TotalBuckets: 0,
	}

	disclaimer := generateDataQualityDisclaimer(uptime)

	if disclaimer == "" {
		t.Fatal("expected non-empty disclaimer when no data")
	}
}

// --- T164: Failure prominence ---

func TestSortControlsFailuresFirst(t *testing.T) {
	summaries := []controlSummary{
		{ControlID: "ctrl-1", Status: "effective"},
		{ControlID: "ctrl-2", Status: "ineffective"},
		{ControlID: "ctrl-3", Status: "effective"},
		{ControlID: "ctrl-4", Status: "ineffective"},
	}

	sorted := sortControlsFailuresFirst(summaries)

	// First two should be ineffective
	if sorted[0].Status != "ineffective" || sorted[1].Status != "ineffective" {
		t.Error("ineffective controls not sorted first")
	}
	// Last two should be effective
	if sorted[2].Status != "effective" || sorted[3].Status != "effective" {
		t.Error("effective controls not sorted last")
	}
}

func TestGenerateMarkdownReport_FailureProminence(t *testing.T) {
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC)

	evs := []evidence.Evidence{
		makeEvidence("ctrl-ok", now, evidence.StatusEffective, "effective", evidence.PassiveObservation, "okta-mfa"),
		makeEvidence("ctrl-fail", now, evidence.StatusIneffective, "ineffective", evidence.ActiveVerification, "aws-test"),
	}

	statuses := []control.ControlStatus{
		makeControlStatus("ctrl-ok", now, "effective", "high"),
		makeControlStatus("ctrl-fail", now, "ineffective", "medium"),
	}

	opts := reportOptions{
		format: "markdown",
		from:   from,
		to:     to,
	}

	var buf bytes.Buffer
	err := generateMarkdownReport(&buf, evs, statuses, opts)
	if err != nil {
		t.Fatalf("generateMarkdownReport returned error: %v", err)
	}

	output := buf.String()

	// Failure control should appear before effective control
	failIdx := strings.Index(output, "ctrl-fail")
	okIdx := strings.Index(output, "ctrl-ok")
	if failIdx == -1 || okIdx == -1 {
		t.Fatal("missing control IDs in output")
	}
	if failIdx > okIdx {
		t.Error("failed control not displayed before effective control (failure prominence)")
	}

	// Failures should have bold/warning markers
	if !strings.Contains(output, "**INEFFECTIVE**") {
		t.Error("ineffective control not displayed with bold marker")
	}
}

// --- T162 cont: Transcript in markdown report ---

func TestGenerateMarkdownReport_TranscriptSummary(t *testing.T) {
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC)

	ev := makeEvidence("ctrl-1", now, evidence.StatusEffective, "effective", evidence.ActiveVerification, "okta-mfa-test")
	ev.TestTranscript = &evidence.TestTranscript{
		ActionsAttempted: []evidence.TranscriptAction{
			{Action: "Attempt login without MFA"},
		},
		Observations: []evidence.TranscriptObservation{
			{Observation: "Login blocked", Expected: true},
		},
		CleanupActions: []evidence.TranscriptCleanup{
			{Action: "Remove test user", Success: true},
		},
	}

	evs := []evidence.Evidence{ev}
	statuses := []control.ControlStatus{
		makeControlStatus("ctrl-1", now, "effective", "high"),
	}

	opts := reportOptions{
		format: "markdown",
		from:   from,
		to:     to,
	}

	var buf bytes.Buffer
	err := generateMarkdownReport(&buf, evs, statuses, opts)
	if err != nil {
		t.Fatalf("generateMarkdownReport returned error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "Attempt login without MFA") {
		t.Error("transcript actions not included in markdown report")
	}
	if !strings.Contains(output, "Login blocked") {
		t.Error("transcript observations not included in markdown report")
	}
}

// --- T165: CLI flag parsing tests ---

func TestParsePeriod(t *testing.T) {
	from, to, err := parsePeriod("2026-01-01:2026-06-30")
	if err != nil {
		t.Fatalf("parsePeriod returned error: %v", err)
	}

	expectedFrom := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expectedTo := time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC)

	if !from.Equal(expectedFrom) {
		t.Errorf("from = %v, want %v", from, expectedFrom)
	}
	if !to.Equal(expectedTo) {
		t.Errorf("to = %v, want %v", to, expectedTo)
	}
}

func TestParsePeriod_InvalidFormat(t *testing.T) {
	_, _, err := parsePeriod("2026-01-01")
	if err == nil {
		t.Error("expected error for invalid period format, got nil")
	}
}

func TestParsePeriod_InvalidDate(t *testing.T) {
	_, _, err := parsePeriod("not-a-date:also-not")
	if err == nil {
		t.Error("expected error for invalid dates, got nil")
	}
}

// --- Helpers ---

func makeEvidence(controlID string, ts time.Time, statusID evidence.StatusID, status string, confidence evidence.ConfidenceLevel, module string) evidence.Evidence {
	return evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       controlID,
		Time:            ts,
		StatusID:        statusID,
		Status:          status,
		ConfidenceLevel: confidence,
		Metadata: evidence.Metadata{
			Module: evidence.ModuleInfo{
				Name: module,
			},
			Source: evidence.SourceInfo{
				System: "test-system",
			},
		},
		Attestation: evidence.AttestationRef{
			DSSEEnvelopeRef: "ref-" + controlID,
			Digest:          "sha256:abc",
		},
	}
}

func makeControlStatus(controlID string, ts time.Time, status, confidence string) control.ControlStatus {
	return control.ControlStatus{
		ID:         uuid.New(),
		ControlID:  controlID,
		Timestamp:  ts,
		Status:     status,
		Confidence: confidence,
	}
}

func boolPtr(b bool) *bool {
	return &b
}
