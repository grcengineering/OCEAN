package okta

import "github.com/grcengineering/ocean/internal/module"

// RegisterAll registers all Okta testers with the given registry.
func RegisterAll(reg *module.Registry) {
	reg.RegisterTester(&MFABypassTester{})
}
