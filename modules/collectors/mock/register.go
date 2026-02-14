package mock

import "github.com/grcengineering/ocean/internal/module"

// RegisterAll registers all mock collectors with the given registry.
func RegisterAll(reg *module.Registry) {
	reg.RegisterCollector(&Collector{})
	reg.RegisterCollector(&NetworkCollector{})
}
