package module

import (
	"context"

	"github.com/grcengineering/ocean/internal/evidence"
)

// Collector gathers passive evidence from source systems. Collectors are
// read-only modules that observe system state without modifying it, producing
// evidence at the "passive_observation" confidence level.
type Collector interface {
	Module
	Collect(ctx context.Context, config map[string]string) ([]evidence.Evidence, error)
}
