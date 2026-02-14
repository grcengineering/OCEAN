package eval

import (
	"fmt"
	"sort"
)

// presets maps preset names to their CEL expression equivalents. These provide
// common evaluation patterns that control authors can reference by name
// instead of writing raw CEL expressions.
var presets = map[string]string{
	// all_effective: All evidence must be effective, with no ineffective records.
	"all_effective": "status_counts.ineffective == 0 && status_counts.effective > 0",

	// any_effective: At least one evidence record is effective.
	"any_effective": "status_counts.effective > 0",

	// active_verified: Active verification evidence is present, and no
	// evidence is ineffective.
	"active_verified": "has_active && status_counts.ineffective == 0 && status_counts.effective > 0",
}

// ExpandPreset returns the CEL expression string for a named preset.
// Returns an error if the preset name is not recognized.
func ExpandPreset(name string) (string, error) {
	expr, ok := presets[name]
	if !ok {
		available := ListPresets()
		return "", fmt.Errorf("unknown preset %q; available presets: %v", name, available)
	}
	return expr, nil
}

// ResolveExpression determines the final CEL expression to evaluate given
// a control's evaluation logic. If a direct CEL expression is provided, it
// takes precedence over a preset name. Returns an error if neither is provided.
func ResolveExpression(celExpr, presetName string) (string, error) {
	if celExpr != "" {
		return celExpr, nil
	}
	if presetName != "" {
		return ExpandPreset(presetName)
	}
	return "", fmt.Errorf("no CEL expression or preset provided; specify either evaluation.cel or evaluation.preset")
}

// ListPresets returns the sorted names of all available presets.
func ListPresets() []string {
	names := make([]string, 0, len(presets))
	for name := range presets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
