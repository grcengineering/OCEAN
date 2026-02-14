package module

import (
	"context"

	"github.com/grcengineering/ocean/internal/evidence"
)

// Tester performs active control verification by interacting with target
// systems. Testers produce evidence at the "active_verification" confidence
// level and must declare their safety classification and cleanup procedures.
type Tester interface {
	Module
	SafetyClass() SafetyClassification
	EnvironmentScope() EnvironmentScope
	PreFlightChecks() []string
	CleanupProcedures() []string
	Test(ctx context.Context, config map[string]string) ([]evidence.Evidence, error)
}
