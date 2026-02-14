package mock

import "github.com/grcengineering/ocean/internal/module"

// RegisterAll registers all mock testers with the given registry.
func RegisterAll(reg *module.Registry) {
	reg.RegisterTester(&MockTester{})
}
