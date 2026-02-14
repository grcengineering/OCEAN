package github

import "github.com/grcengineering/ocean/internal/module"

// RegisterAll registers all GitHub testers with the given registry.
func RegisterAll(reg *module.Registry) {
	reg.RegisterTester(&SecretPushTester{})
}
