package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPrintOutput_JSON(t *testing.T) {
	data := map[string]string{"key": "value"}
	var buf bytes.Buffer

	if err := PrintOutput(&buf, data, "json"); err != nil {
		t.Fatalf("PrintOutput(json) returned error: %v", err)
	}

	output := buf.String()

	// Must be valid JSON
	var parsed map[string]string
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, output)
	}

	if parsed["key"] != "value" {
		t.Errorf("parsed[\"key\"] = %q, want %q", parsed["key"], "value")
	}
}

func TestPrintOutput_JSON_PrettyPrinted(t *testing.T) {
	data := map[string]string{"key": "value"}
	var buf bytes.Buffer

	if err := PrintOutput(&buf, data, "json"); err != nil {
		t.Fatalf("PrintOutput(json) returned error: %v", err)
	}

	output := buf.String()
	// Pretty-printed JSON should contain newlines and indentation
	if !strings.Contains(output, "\n") {
		t.Error("JSON output is not pretty-printed (no newlines)")
	}
}

func TestPrintOutput_YAML(t *testing.T) {
	data := map[string]string{"key": "value"}
	var buf bytes.Buffer

	if err := PrintOutput(&buf, data, "yaml"); err != nil {
		t.Fatalf("PrintOutput(yaml) returned error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "key: value") {
		t.Errorf("YAML output does not contain expected content.\ngot: %s", output)
	}
}

func TestPrintOutput_DefaultIsJSON(t *testing.T) {
	data := map[string]string{"key": "value"}
	var buf bytes.Buffer

	if err := PrintOutput(&buf, data, ""); err != nil {
		t.Fatalf("PrintOutput(\"\") returned error: %v", err)
	}

	output := buf.String()
	var parsed map[string]string
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("default format output is not valid JSON: %v\noutput: %s", err, output)
	}
}

func TestPrintOutput_YAML_RawJSONMessage(t *testing.T) {
	// Simulates the json.RawMessage problem: YAML should render the JSON
	// content as structured data, not as a byte array.
	type withRaw struct {
		Name string          `json:"name"`
		Data json.RawMessage `json:"data"`
	}
	data := withRaw{
		Name: "test",
		Data: json.RawMessage(`{"inner": "value"}`),
	}
	var buf bytes.Buffer

	if err := PrintOutput(&buf, data, "yaml"); err != nil {
		t.Fatalf("PrintOutput(yaml) returned error: %v", err)
	}

	output := buf.String()
	// The output should contain the structured data, not byte values
	if strings.Contains(output, "- 123") {
		t.Errorf("YAML output contains byte array instead of structured data.\ngot: %s", output)
	}
	if !strings.Contains(output, "inner") {
		t.Errorf("YAML output missing expected 'inner' key.\ngot: %s", output)
	}
}

func TestPrintOutput_NestedStructure(t *testing.T) {
	data := map[string]interface{}{
		"name": "test",
		"nested": map[string]interface{}{
			"inner": "value",
			"count": 42,
		},
	}
	var buf bytes.Buffer

	if err := PrintOutput(&buf, data, "json"); err != nil {
		t.Fatalf("PrintOutput(json) returned error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	nested, ok := parsed["nested"].(map[string]interface{})
	if !ok {
		t.Fatal("nested field is not a map")
	}
	if nested["inner"] != "value" {
		t.Errorf("nested.inner = %v, want %q", nested["inner"], "value")
	}
}
