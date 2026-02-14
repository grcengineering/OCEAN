package module

import (
	"fmt"
	"sort"
	"sync"
)

// ModuleInfo holds metadata about a registered module, suitable for
// display in CLI listings and API responses.
type ModuleInfo struct {
	ID                   string
	Name                 string
	Version              string
	Type                 string // "collector" or "tester"
	SourceSystem         string
	SafetyClassification string // empty for collectors, classification for testers
	EnvironmentScope     string // empty for collectors, scope for testers
}

// Registry holds all registered modules, providing thread-safe access
// to collectors and testers by their unique identifiers.
type Registry struct {
	mu         sync.RWMutex
	collectors map[string]Collector
	testers    map[string]Tester
}

// NewRegistry creates an empty module registry.
func NewRegistry() *Registry {
	return &Registry{
		collectors: make(map[string]Collector),
		testers:    make(map[string]Tester),
	}
}

// RegisterCollector adds a collector to the registry.
func (r *Registry) RegisterCollector(c Collector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.collectors[c.ID()] = c
}

// RegisterTester adds a tester to the registry.
func (r *Registry) RegisterTester(t Tester) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.testers[t.ID()] = t
}

// GetCollector returns the collector with the given ID or an error if not found.
func (r *Registry) GetCollector(id string) (Collector, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.collectors[id]
	if !ok {
		return nil, fmt.Errorf("collector %q not found", id)
	}
	return c, nil
}

// GetTester returns the tester with the given ID or an error if not found.
func (r *Registry) GetTester(id string) (Tester, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.testers[id]
	if !ok {
		return nil, fmt.Errorf("tester %q not found", id)
	}
	return t, nil
}

// ListCollectors returns all registered collectors.
func (r *Registry) ListCollectors() []Collector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Collector, 0, len(r.collectors))
	for _, c := range r.collectors {
		result = append(result, c)
	}
	return result
}

// ListTesters returns all registered testers.
func (r *Registry) ListTesters() []Tester {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Tester, 0, len(r.testers))
	for _, t := range r.testers {
		result = append(result, t)
	}
	return result
}

// ListAll returns all registered modules (both collectors and testers).
func (r *Registry) ListAll() []Module {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Module, 0, len(r.collectors)+len(r.testers))
	for _, c := range r.collectors {
		result = append(result, c)
	}
	for _, t := range r.testers {
		result = append(result, t)
	}
	return result
}

// GetModule returns a Module (collector or tester) by ID, or an error if not found.
func (r *Registry) GetModule(id string) (Module, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if c, ok := r.collectors[id]; ok {
		return c, nil
	}
	if t, ok := r.testers[id]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("module %q not found", id)
}

// ListModules returns metadata for all registered modules, sorted by ID.
func (r *Registry) ListModules() []ModuleInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	infos := make([]ModuleInfo, 0, len(r.collectors)+len(r.testers))

	for _, c := range r.collectors {
		infos = append(infos, ModuleInfo{
			ID:           c.ID(),
			Name:         c.Name(),
			Version:      c.Version(),
			Type:         "collector",
			SourceSystem: c.SourceSystem(),
		})
	}

	for _, t := range r.testers {
		infos = append(infos, ModuleInfo{
			ID:                   t.ID(),
			Name:                 t.Name(),
			Version:              t.Version(),
			Type:                 "tester",
			SourceSystem:         t.SourceSystem(),
			SafetyClassification: string(t.SafetyClass()),
			EnvironmentScope:     string(t.EnvironmentScope()),
		})
	}

	sort.Slice(infos, func(i, j int) bool {
		return infos[i].ID < infos[j].ID
	})

	return infos
}

// ListByType returns metadata for modules of the given type ("collector" or "tester"),
// sorted by ID.
func (r *Registry) ListByType(moduleType string) []ModuleInfo {
	all := r.ListModules()
	filtered := make([]ModuleInfo, 0)
	for _, info := range all {
		if info.Type == moduleType {
			filtered = append(filtered, info)
		}
	}
	return filtered
}

// ListBySourceSystem returns metadata for modules targeting the given source system,
// sorted by ID.
func (r *Registry) ListBySourceSystem(system string) []ModuleInfo {
	all := r.ListModules()
	filtered := make([]ModuleInfo, 0)
	for _, info := range all {
		if info.SourceSystem == system {
			filtered = append(filtered, info)
		}
	}
	return filtered
}
