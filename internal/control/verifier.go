package control

import (
	"context"
	"fmt"
	"strings"

	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

// VerifyResult holds the outcome of a dual-mode verification.
type VerifyResult struct {
	Control      *Control              `json:"control"`
	Status       *ControlStatus        `json:"status"`
	Evidences    []evidence.Evidence   `json:"evidences"`
	SkippedTests []string              `json:"skipped_tests,omitempty"`
}

// Verifier orchestrates dual-mode control verification by running both
// passive collectors and active testers, then evaluating the combined
// evidence to produce a unified control status.
type Verifier struct {
	Registry *module.Registry
	Executor *module.Executor
}

// NewVerifier creates a verifier backed by the given registry and executor.
func NewVerifier(reg *module.Registry, exec *module.Executor) *Verifier {
	return &Verifier{
		Registry: reg,
		Executor: exec,
	}
}

// VerifyControl performs dual-mode verification:
//  1. Execute all referenced collectors (passive evidence)
//  2. Execute authorized testers (skip unavailable ones)
//  3. Combine evidence from both modes
//  4. Evaluate combined evidence to determine control status
//  5. Return VerifyResult with control status, evidence, and any skipped tests
func (v *Verifier) VerifyControl(ctx context.Context, ctrl *Control) (*VerifyResult, error) {
	result := &VerifyResult{
		Control: ctrl,
	}

	var allEvidence []evidence.Evidence

	// Step 1: Execute all collectors (passive evidence).
	for _, ref := range ctrl.Collectors {
		evs, err := v.Executor.ExecuteCollector(ctx, ref.ModuleID, nil)
		if err != nil {
			// If a collector fails, record the error but continue.
			// A missing collector is a configuration problem, not a verification failure.
			result.SkippedTests = append(result.SkippedTests, fmt.Sprintf("collector:%s", ref.ModuleID))
			continue
		}
		allEvidence = append(allEvidence, evs...)
	}

	// Step 2: Execute testers (active verification).
	for _, ref := range ctrl.Testers {
		// Check if the tester is available in the registry.
		_, err := v.Registry.GetTester(ref.ModuleID)
		if err != nil {
			// Tester not found: skip it, don't fail the whole verification.
			result.SkippedTests = append(result.SkippedTests, ref.ModuleID)
			continue
		}

		evs, err := v.Executor.ExecuteTester(ctx, ref.ModuleID, nil)
		if err != nil {
			// Tester execution failed: skip and record.
			result.SkippedTests = append(result.SkippedTests, ref.ModuleID)
			continue
		}
		allEvidence = append(allEvidence, evs...)
	}

	result.Evidences = allEvidence

	// Step 3: Evaluate combined evidence.
	// Use composite evaluation when the control defines CEL/preset logic,
	// which provides per-component breakdown and handles partial availability.
	var cs *ControlStatus
	var evalErr error
	if isCompositeControl(ctrl) {
		cs, evalErr = CompositeEvaluateControl(ctrl, allEvidence)
	} else {
		cs, evalErr = EvaluateControl(ctrl, allEvidence)
	}
	if evalErr != nil {
		return nil, fmt.Errorf("evaluating control %s: %w", ctrl.ID, evalErr)
	}

	// Append skipped test info to evaluation details if any tests were skipped.
	if len(result.SkippedTests) > 0 {
		skippedNote := fmt.Sprintf("; skipped: [%s]", strings.Join(result.SkippedTests, ", "))
		cs.EvaluationDetails += skippedNote
	}

	result.Status = cs

	return result, nil
}

// isCompositeControl returns true if a control defines CEL or preset evaluation
// logic, indicating it should be evaluated using the composite evaluator which
// provides per-component breakdown and handles partial source availability.
func isCompositeControl(ctrl *Control) bool {
	return ctrl.EvaluationLogic.CELExpression != "" || ctrl.EvaluationLogic.Preset != ""
}
