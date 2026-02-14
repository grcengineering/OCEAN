package aws

import "github.com/grcengineering/ocean/internal/module"

// RegisterAll registers all AWS testers with the given registry.
func RegisterAll(reg *module.Registry) {
	reg.RegisterTester(&PublicAccessTester{})
}
