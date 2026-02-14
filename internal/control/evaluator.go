package control

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/eval"
	"github.com/grcengineering/ocean/internal/evidence"
)

// ControlStatus represents the evaluated state of a control at a point in
// time, derived from one or more evidence records. This is the output of
// the evaluation pipeline and the input to dashboards and reports.
type ControlStatus struct {
	ID                       uuid.UUID   `json:"id"`
	ControlID                string      `json:"control_id"`
	Timestamp                time.Time   `json:"timestamp"`
	Status                   string      `json:"status"`     // effective, ineffective, unknown, partial
	Confidence               string      `json:"confidence"` // high, medium, low
	EvidenceIDs              []uuid.UUID `json:"evidence_ids"`
	EvaluationDetails        string      `json:"evaluation_details"`
	EvaluationAttestationRef string      `json:"evaluation_attestation_ref,omitempty"`
}

// UptimeResult holds the result of an uptime calculation.
type UptimeResult struct {
	ControlID          string    `json:"control_id"`
	FromTime           time.Time `json:"from"`
	ToTime             time.Time `json:"to"`
	TotalBuckets       int       `json:"total_buckets"`
	EffectiveBuckets   int       `json:"effective_buckets"`
	IneffectiveBuckets int       `json:"ineffective_buckets"`
	GapBuckets         int       `json:"gap_buckets"`
	UptimePercent      float64   `json:"uptime_percent"`
}

// CalculateUptime computes the uptime percentage for a control over a time range.
// It buckets control statuses by the given interval (e.g., 24h for daily).
// Gaps (periods with no data) count as unknown, NOT effective.
// UptimePercent = effective / (effective + ineffective) * 100, or 0 if all gaps.
func CalculateUptime(statuses []ControlStatus, from, to time.Time, interval time.Duration) UptimeResult {
	// Derive control ID from the first status, if available.
	controlID := ""
	if len(statuses) > 0 {
		controlID = statuses[0].ControlID
	}

	result := UptimeResult{
		ControlID: controlID,
		FromTime:  from,
		ToTime:    to,
	}

	// Edge cases: invalid range or zero interval.
	if !from.Before(to) || interval <= 0 {
		return result
	}

	// Sort statuses by timestamp for efficient bucket assignment.
	sorted := make([]ControlStatus, len(statuses))
	copy(sorted, statuses)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	// Create time buckets from 'from' to 'to'.
	var bucketStarts []time.Time
	for t := from; t.Before(to); t = t.Add(interval) {
		bucketStarts = append(bucketStarts, t)
	}

	result.TotalBuckets = len(bucketStarts)

	// For each bucket, find the most recent status within the bucket window.
	for _, bucketStart := range bucketStarts {
		bucketEnd := bucketStart.Add(interval)

		var mostRecent *ControlStatus
		for i := range sorted {
			s := &sorted[i]
			// Status falls in this bucket if its timestamp is >= bucketStart and < bucketEnd.
			if (s.Timestamp.Equal(bucketStart) || s.Timestamp.After(bucketStart)) &&
				s.Timestamp.Before(bucketEnd) {
				if mostRecent == nil || s.Timestamp.After(mostRecent.Timestamp) {
					mostRecent = s
				}
			}
		}

		if mostRecent == nil {
			result.GapBuckets++
		} else if mostRecent.Status == "effective" {
			result.EffectiveBuckets++
		} else {
			result.IneffectiveBuckets++
		}
	}

	// UptimePercent = effective / (effective + ineffective) * 100.
	// If all gaps (no effective or ineffective), uptime is 0.
	nonGap := result.EffectiveBuckets + result.IneffectiveBuckets
	if nonGap > 0 {
		result.UptimePercent = float64(result.EffectiveBuckets) / float64(nonGap) * 100.0
	}

	return result
}

// staleness threshold: evidence older than this is considered stale.
const stalenessThreshold = 24 * time.Hour

// EvaluateControl determines the control status from a set of evidence records.
// It considers both passive collection and active verification evidence.
// When passive evidence says "effective" but active says "ineffective",
// active takes precedence (this is a CRITICAL finding).
func EvaluateControl(ctrl *Control, evidences []evidence.Evidence) (*ControlStatus, error) {
	now := time.Now().UTC()

	cs := &ControlStatus{
		ID:        uuid.New(),
		ControlID: ctrl.ID,
		Timestamp: now,
	}

	// No evidence => unknown with low confidence.
	if len(evidences) == 0 {
		cs.Status = "unknown"
		cs.Confidence = "low"
		cs.EvaluationDetails = "no evidence available"
		return cs, nil
	}

	// Collect evidence IDs.
	for _, ev := range evidences {
		cs.EvidenceIDs = append(cs.EvidenceIDs, ev.ID)
	}

	// Classify evidence by type.
	var passiveEvs, activeEvs []evidence.Evidence
	for _, ev := range evidences {
		switch ev.ConfidenceLevel {
		case evidence.PassiveObservation:
			passiveEvs = append(passiveEvs, ev)
		case evidence.ActiveVerification:
			activeEvs = append(activeEvs, ev)
		}
	}

	// Check for discrepancy: passive effective + active ineffective.
	hasDiscrepancy := false
	passiveEffective := allStatusMatch(passiveEvs, evidence.StatusEffective)
	activeIneffective := anyStatusMatch(activeEvs, evidence.StatusIneffective)

	if len(passiveEvs) > 0 && len(activeEvs) > 0 && passiveEffective && activeIneffective {
		hasDiscrepancy = true
	}

	// Determine overall status.
	if hasDiscrepancy {
		// Active takes precedence: this is a CRITICAL discrepancy.
		cs.Status = "ineffective"
		cs.EvaluationDetails = fmt.Sprintf(
			"CRITICAL discrepancy: passive evidence indicates effective but active verification found ineffective; "+
				"active evidence takes precedence (passive=%d effective, active=%d with ineffective findings)",
			len(passiveEvs), len(activeEvs))
	} else {
		cs.Status = determineStatus(evidences)
		cs.EvaluationDetails = buildEvaluationDetails(evidences, passiveEvs, activeEvs)
	}

	// Determine confidence.
	cs.Confidence = DetermineConfidence(evidences)

	return cs, nil
}

// CELEvaluateControl evaluates a control using its CEL expression (or preset)
// against a set of evidence records. This provides user-defined evaluation
// logic on top of the basic EvaluateControl function.
//
// The function:
//  1. Resolves the CEL expression (from direct CEL or preset expansion)
//  2. Compiles the expression with syntax and type checking
//  3. Evaluates it against the evidence
//  4. Returns a ControlStatus with the expression hash in EvaluationDetails
//
// If celOverride is non-empty, it overrides the control's own evaluation logic
// (supports the --cel CLI flag for ad-hoc expressions).
func CELEvaluateControl(ctrl *Control, evidences []evidence.Evidence, celOverride string) (*ControlStatus, error) {
	now := time.Now().UTC()

	cs := &ControlStatus{
		ID:        uuid.New(),
		ControlID: ctrl.ID,
		Timestamp: now,
	}

	// Collect evidence IDs.
	for _, ev := range evidences {
		cs.EvidenceIDs = append(cs.EvidenceIDs, ev.ID)
	}

	// No evidence => unknown with low confidence.
	if len(evidences) == 0 {
		cs.Status = "unknown"
		cs.Confidence = "low"
		cs.EvaluationDetails = "no evidence available for CEL evaluation"
		return cs, nil
	}

	// Resolve the CEL expression.
	celExpr := celOverride
	presetName := ""
	if celExpr == "" {
		celExpr = ctrl.EvaluationLogic.CELExpression
		presetName = ctrl.EvaluationLogic.Preset
	}

	expr, err := eval.ResolveExpression(celExpr, presetName)
	if err != nil {
		return nil, fmt.Errorf("resolving evaluation expression for control %s: %w", ctrl.ID, err)
	}

	// Compile the expression.
	compiled, err := eval.CompileExpression(expr)
	if err != nil {
		return nil, fmt.Errorf("compiling CEL expression for control %s: %w", ctrl.ID, err)
	}

	// Evaluate.
	result, err := eval.Evaluate(compiled, evidences)
	if err != nil {
		// T104: evaluation errors result in unknown status, not a crash.
		cs.Status = "unknown"
		cs.Confidence = "low"
		cs.EvaluationDetails = fmt.Sprintf("CEL evaluation error: %v", err)
		return cs, nil
	}

	// Compute expression hash for auditability.
	exprHash := eval.ContentAddress(expr)
	ctrl.EvaluationExpressionHash = exprHash

	// Map CEL result to status.
	if result {
		cs.Status = "effective"
	} else {
		cs.Status = "ineffective"
	}

	// Determine confidence using the standard logic.
	cs.Confidence = DetermineConfidence(evidences)

	// Build evaluation details with expression hash.
	cs.EvaluationDetails = fmt.Sprintf("CEL evaluation: expr=%s, hash=%s, verdict=%s",
		expr, exprHash, cs.Status)

	return cs, nil
}

// determineStatus computes the overall status string from evidence records.
func determineStatus(evidences []evidence.Evidence) string {
	hasEffective := false
	hasIneffective := false
	hasOther := false

	for _, ev := range evidences {
		switch ev.StatusID {
		case evidence.StatusEffective:
			hasEffective = true
		case evidence.StatusIneffective:
			hasIneffective = true
		default:
			hasOther = true
		}
	}

	if hasIneffective {
		return "ineffective"
	}
	if hasEffective && !hasOther {
		return "effective"
	}
	if hasEffective && hasOther {
		return "partial"
	}
	return "unknown"
}

// DetermineConfidence computes the confidence level based on evidence types.
//
// Rules:
//   - "high": Both passive AND active evidence present, and they agree
//   - "medium": Only one type present (passive-only or active-only)
//   - "low": Stale evidence (>24h old), incomplete, or disagreement resolved
func DetermineConfidence(evidences []evidence.Evidence) string {
	if len(evidences) == 0 {
		return "low"
	}

	now := time.Now().UTC()

	// Check for staleness first -- any stale evidence degrades confidence.
	for _, ev := range evidences {
		if now.Sub(ev.Time) > stalenessThreshold {
			return "low"
		}
	}

	// Classify by type.
	var passiveEvs, activeEvs []evidence.Evidence
	for _, ev := range evidences {
		switch ev.ConfidenceLevel {
		case evidence.PassiveObservation:
			passiveEvs = append(passiveEvs, ev)
		case evidence.ActiveVerification:
			activeEvs = append(activeEvs, ev)
		}
	}

	hasPassive := len(passiveEvs) > 0
	hasActive := len(activeEvs) > 0

	// If both types present, check for agreement.
	if hasPassive && hasActive {
		passiveStatus := dominantStatus(passiveEvs)
		activeStatus := dominantStatus(activeEvs)
		if passiveStatus == activeStatus {
			return "high"
		}
		// Disagreement => low confidence.
		return "low"
	}

	// Only one type present.
	if hasPassive || hasActive {
		return "medium"
	}

	// No recognized confidence levels.
	return "low"
}

// allStatusMatch returns true if all evidence records have the given status.
func allStatusMatch(evs []evidence.Evidence, status evidence.StatusID) bool {
	if len(evs) == 0 {
		return false
	}
	for _, ev := range evs {
		if ev.StatusID != status {
			return false
		}
	}
	return true
}

// anyStatusMatch returns true if any evidence record has the given status.
func anyStatusMatch(evs []evidence.Evidence, status evidence.StatusID) bool {
	for _, ev := range evs {
		if ev.StatusID == status {
			return true
		}
	}
	return false
}

// dominantStatus returns the most severe status from a set of evidence records.
// Ineffective > Unknown/Other > Effective.
func dominantStatus(evs []evidence.Evidence) evidence.StatusID {
	if len(evs) == 0 {
		return evidence.StatusUnknown
	}

	hasIneffective := false
	hasEffective := false

	for _, ev := range evs {
		switch ev.StatusID {
		case evidence.StatusIneffective:
			hasIneffective = true
		case evidence.StatusEffective:
			hasEffective = true
		}
	}

	if hasIneffective {
		return evidence.StatusIneffective
	}
	if hasEffective {
		return evidence.StatusEffective
	}
	return evidence.StatusUnknown
}

// buildEvaluationDetails creates a human-readable summary of the evaluation.
func buildEvaluationDetails(all, passive, active []evidence.Evidence) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("evaluated %d evidence records", len(all)))
	if len(passive) > 0 {
		parts = append(parts, fmt.Sprintf("%d passive", len(passive)))
	}
	if len(active) > 0 {
		parts = append(parts, fmt.Sprintf("%d active", len(active)))
	}
	return strings.Join(parts, ", ")
}
