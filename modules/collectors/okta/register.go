package okta

import "github.com/grcengineering/ocean/internal/module"

// RegisterAll registers all Okta collectors with the given registry.
func RegisterAll(reg *module.Registry) {
	reg.RegisterCollector(&MFAPolicyCollector{})
}
