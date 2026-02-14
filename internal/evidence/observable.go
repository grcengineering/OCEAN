package evidence

import (
	"encoding/json"
	"strings"
)

// observablePatterns maps field-name substrings to observable types.
// When a JSON key contains the substring, its string value is classified
// as the corresponding observable type.
var observablePatterns = []struct {
	substrings []string
	obsType    string
}{
	{substrings: []string{"user", "email", "account"}, obsType: "user"},
	{substrings: []string{"ip", "address"}, obsType: "ip"},
	{substrings: []string{"resource", "arn", "id"}, obsType: "resource"},
	{substrings: []string{"domain", "url", "host"}, obsType: "domain"},
}

// ExtractObservables scans raw evidence data (JSON) to surface key indicators
// such as usernames, IP addresses, resource identifiers, and domain names.
// It walks the JSON recursively, matching field names against known patterns
// and returning a deduplicated set of observables.
func ExtractObservables(rawData json.RawMessage) []Observable {
	if rawData == nil {
		return nil
	}

	var parsed interface{}
	if err := json.Unmarshal(rawData, &parsed); err != nil {
		return nil
	}

	seen := make(map[Observable]struct{})
	var result []Observable

	walkJSON("", parsed, func(key string, value string) {
		lowerKey := strings.ToLower(key)
		for _, pattern := range observablePatterns {
			for _, substr := range pattern.substrings {
				if strings.Contains(lowerKey, substr) {
					obs := Observable{Type: pattern.obsType, Value: value}
					if _, exists := seen[obs]; !exists {
						seen[obs] = struct{}{}
						result = append(result, obs)
					}
					return // first match wins; avoid duplicate type classification
				}
			}
		}
	})

	return result
}

// walkJSON recursively traverses a parsed JSON value, calling fn for every
// leaf string value with its associated key name.
func walkJSON(key string, value interface{}, fn func(key string, value string)) {
	switch v := value.(type) {
	case map[string]interface{}:
		for k, child := range v {
			walkJSON(k, child, fn)
		}
	case []interface{}:
		for _, item := range v {
			walkJSON(key, item, fn)
		}
	case string:
		if v != "" {
			fn(key, v)
		}
	}
}
