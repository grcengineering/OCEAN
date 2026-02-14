package cli

import (
	"encoding/json"
	"io"

	"gopkg.in/yaml.v3"
)

// PrintOutput writes data in the specified format to the writer.
// Supported formats are "json" (default) and "yaml".
//
// For YAML output, data is round-tripped through JSON first so that
// json.RawMessage fields (like Evidence.RawData) render as structured
// maps instead of raw byte arrays.
func PrintOutput(w io.Writer, data interface{}, format string) error {
	switch format {
	case "yaml":
		return printYAML(w, data)
	case "json":
		fallthrough
	default:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	}
}

// printYAML marshals data through JSON first to normalize types like
// json.RawMessage, then outputs clean YAML.
func printYAML(w io.Writer, data interface{}) error {
	// Round-trip through JSON so json.RawMessage is expanded.
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	var generic interface{}
	if err := json.Unmarshal(jsonBytes, &generic); err != nil {
		return err
	}

	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	defer enc.Close()
	return enc.Encode(generic)
}
