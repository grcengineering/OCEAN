package mock

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

// NetworkCollector is a mock collector that returns network-related evidence,
// simulating a WAF configuration check. It can be used alongside the primary
// mock collector to test composite control evaluation with multiple sources.
type NetworkCollector struct{}

// Compile-time interface check.
var _ module.Collector = (*NetworkCollector)(nil)

func (c *NetworkCollector) ID() string            { return "mock.network" }
func (c *NetworkCollector) Name() string          { return "Mock Network Collector" }
func (c *NetworkCollector) Version() string       { return "0.1.0" }
func (c *NetworkCollector) SourceSystem() string  { return "mock" }
func (c *NetworkCollector) EvidenceTypes() []int  { return []int{1002} }
func (c *NetworkCollector) CredentialRequirements() []module.CredentialReq { return nil }

// Collect returns a single evidence record representing a WAF configuration
// check, simulating verification that a Web Application Firewall is properly
// configured to protect application servers.
func (c *NetworkCollector) Collect(_ context.Context, _ map[string]string) ([]evidence.Evidence, error) {
	now := time.Now().UTC()

	rawData := map[string]interface{}{
		"waf_config": map[string]interface{}{
			"enabled":          true,
			"mode":             "block",
			"rule_sets":        []string{"OWASP-CRS-3.3", "custom-rules-v2"},
			"rate_limiting":    true,
			"geo_blocking":     false,
			"bot_protection":   true,
			"ssl_termination":  true,
		},
		"protected_origins": 3,
		"blocked_requests_24h": 1247,
		"last_rule_update":     "2026-01-20T14:00:00Z",
	}
	rawJSON, _ := json.Marshal(rawData)

	ev := evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "waf.protection",
		ClassUID:        1002,
		CategoryUID:     4, // Network Activity
		ActivityID:      1, // Config Check
		Time:            now,
		ConfidenceLevel: evidence.PassiveObservation,
		Metadata: evidence.Metadata{
			Module: evidence.ModuleInfo{
				Name:    "mock.network",
				Version: "0.1.0",
				Type:    "collector",
			},
			Source: evidence.SourceInfo{
				System:     "mock",
				APIVersion: "v1",
				Endpoint:   "/api/v1/waf/config",
			},
			ProcessedTime: now,
		},
		Observables: []evidence.Observable{
			{Type: "resource", Value: "waf_global_config"},
			{Type: "resource", Value: "waf_rule_sets"},
		},
		StatusID: evidence.StatusEffective,
		Status:   "WAF is enabled in block mode with current rule sets",
		RawData:  rawJSON,
		Findings: []evidence.Finding{
			{
				Title:       "WAF Active",
				Description: "WAF is enabled in block mode with OWASP CRS 3.3 and custom rules",
				SeverityID:  0,
			},
		},
	}

	return []evidence.Evidence{ev}, nil
}
