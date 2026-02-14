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

// ComponentResult holds the evaluation result for a single component
// (collector or tester) within a composite control evaluation.
type ComponentResult struct {
	ModuleID   string `json:"module_id"`
	ModuleType string `json:"module_type"` // "collector" or "tester"
	Status     string `json:"status"`      // effective, ineffective, unknown, unavailable
	Confidence string `json:"confidence"`  // high, medium, low
}

// CompositeEvaluateControl evaluates a composite control that references
// multiple collectors and/or testers. It:
//  1. Groups evidence by source module (from evidence Metadata.Module.Name)
//  2. Builds a per-component breakdown showing each source's status
//  3. Runs the control's CEL expression against the combined evidence map
//  4. Includes per-component breakdown in EvaluationDetails
//
// T105: Composite control evaluation
// T106: Per-component breakdown in evaluation_details
// T107: Partial source availability handling
func CompositeEvaluateControl(ctrl *Control, evidences []evidence.Evidence) (*ControlStatus, error) {
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
		cs.EvaluationDetails = "no evidence available for composite evaluation"
		return cs, nil
	}

	// Collect evidence IDs.
	for _, ev := range evidences {
		cs.EvidenceIDs = append(cs.EvidenceIDs, ev.ID)
	}

	// Group evidence by source module.
	grouped := groupEvidenceBySource(evidences)

	// Build per-component breakdown (T106, T107).
	components := buildComponentBreakdown(ctrl, grouped)

	// Resolve and evaluate the CEL expression against all evidence.
	celExpr := ctrl.EvaluationLogic.CELExpression
	presetName := ctrl.EvaluationLogic.Preset

	expr, err := eval.ResolveExpression(celExpr, presetName)
	if err != nil {
		return nil, fmt.Errorf("resolving evaluation expression for composite control %s: %w", ctrl.ID, err)
	}

	compiled, err := eval.CompileExpression(expr)
	if err != nil {
		return nil, fmt.Errorf("compiling CEL expression for composite control %s: %w", ctrl.ID, err)
	}

	result, err := eval.Evaluate(compiled, evidences)
	if err != nil {
		// CEL evaluation errors result in unknown status, not a crash.
		cs.Status = "unknown"
		cs.Confidence = "low"
		cs.EvaluationDetails = fmt.Sprintf("composite CEL evaluation error: %v; components: %s",
			err, formatComponentBreakdown(components))
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

	// Build evaluation details with per-component breakdown (T106).
	cs.EvaluationDetails = fmt.Sprintf(
		"composite evaluation: expr=%s, hash=%s, verdict=%s; components: %s",
		expr, exprHash, cs.Status, formatComponentBreakdown(components))

	return cs, nil
}

// groupEvidenceBySource groups evidence records by their source module name.
func groupEvidenceBySource(evidences []evidence.Evidence) map[string][]evidence.Evidence {
	grouped := make(map[string][]evidence.Evidence)
	for _, ev := range evidences {
		moduleName := ev.Metadata.Module.Name
		grouped[moduleName] = append(grouped[moduleName], ev)
	}
	return grouped
}

// buildComponentBreakdown creates a per-component status breakdown for a
// composite control. Each referenced collector and tester gets an entry.
// If a module has no evidence, it is marked as "unavailable" (T107).
func buildComponentBreakdown(ctrl *Control, grouped map[string][]evidence.Evidence) []ComponentResult {
	var components []ComponentResult

	// Process collectors.
	for _, ref := range ctrl.Collectors {
		comp := ComponentResult{
			ModuleID:   ref.ModuleID,
			ModuleType: "collector",
		}

		evs, ok := grouped[ref.ModuleID]
		if !ok || len(evs) == 0 {
			// T107: Missing source marked as unavailable.
			comp.Status = "unavailable"
			comp.Confidence = "low"
		} else {
			comp.Status = determineStatus(evs)
			comp.Confidence = DetermineConfidence(evs)
		}

		components = append(components, comp)
	}

	// Process testers.
	for _, ref := range ctrl.Testers {
		comp := ComponentResult{
			ModuleID:   ref.ModuleID,
			ModuleType: "tester",
		}

		evs, ok := grouped[ref.ModuleID]
		if !ok || len(evs) == 0 {
			// T107: Missing source marked as unavailable.
			comp.Status = "unavailable"
			comp.Confidence = "low"
		} else {
			comp.Status = determineStatus(evs)
			comp.Confidence = DetermineConfidence(evs)
		}

		components = append(components, comp)
	}

	return components
}

// formatComponentBreakdown formats component results into a human-readable
// string for the EvaluationDetails field. Example:
//
//	"mock.test: effective (passive, medium), mock.safety_test: effective (active, medium)"
func formatComponentBreakdown(components []ComponentResult) string {
	// Sort components by module ID for deterministic output.
	sorted := make([]ComponentResult, len(components))
	copy(sorted, components)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ModuleID < sorted[j].ModuleID
	})

	parts := make([]string, 0, len(sorted))
	for _, comp := range sorted {
		parts = append(parts, fmt.Sprintf("%s: %s (%s, %s)",
			comp.ModuleID, comp.Status, comp.ModuleType, comp.Confidence))
	}
	return strings.Join(parts, ", ")
}
