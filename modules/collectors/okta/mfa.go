package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

// MFAPolicyCollector queries Okta's MFA enrollment policies and normalizes
// them into OCEAN evidence records. It detects policy gaps such as inactive
// policies or policies without required factor enrollment.
type MFAPolicyCollector struct{}

// Compile-time interface check.
var _ module.Collector = (*MFAPolicyCollector)(nil)

func (c *MFAPolicyCollector) ID() string           { return "okta.mfa_policy" }
func (c *MFAPolicyCollector) Name() string         { return "Okta MFA Policy Collector" }
func (c *MFAPolicyCollector) Version() string      { return "0.1.0" }
func (c *MFAPolicyCollector) SourceSystem() string { return "okta" }
func (c *MFAPolicyCollector) EvidenceTypes() []int { return []int{1001} }

func (c *MFAPolicyCollector) CredentialRequirements() []module.CredentialReq {
	return []module.CredentialReq{
		{
			Name:        "OKTA_API_TOKEN",
			Type:        "api_token",
			Description: "Okta API token with read access to policies",
			Required:    true,
		},
		{
			Name:        "OKTA_DOMAIN",
			Type:        "domain",
			Description: "Okta organization domain (e.g., example.okta.com)",
			Required:    true,
		},
	}
}

// oktaPolicy represents an Okta MFA enrollment policy from the API response.
type oktaPolicy struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Status     string          `json:"status"`
	Settings   json.RawMessage `json:"settings"`
	Conditions json.RawMessage `json:"conditions"`
}

// oktaPolicySettings represents the settings block of an MFA policy.
type oktaPolicySettings struct {
	Factors map[string]oktaFactor `json:"factors"`
}

// oktaFactor represents a single factor configuration in an MFA policy.
type oktaFactor struct {
	Enroll oktaFactorEnroll `json:"enroll"`
}

// oktaFactorEnroll represents enrollment settings for a factor.
type oktaFactorEnroll struct {
	Self string `json:"self"` // REQUIRED, OPTIONAL, NOT_ALLOWED
}

// Collect queries Okta's MFA enrollment policies and returns normalized
// evidence with findings for any policy gaps detected.
func (c *MFAPolicyCollector) Collect(ctx context.Context, config map[string]string) ([]evidence.Evidence, error) {
	client, err := NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create okta client: %w", err)
	}

	// Query MFA enrollment policies.
	endpoint := "/api/v1/policies?type=MFA_ENROLL"
	url := client.BaseURL() + endpoint

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	body, statusCode, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query MFA policies: %w", err)
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("okta API returned status %d: %s", statusCode, string(body))
	}

	// Parse the policy response.
	var policies []oktaPolicy
	if err := json.Unmarshal(body, &policies); err != nil {
		return nil, fmt.Errorf("failed to parse MFA policies: %w", err)
	}

	now := time.Now().UTC()

	// Analyze policies for gaps.
	var findings []evidence.Finding
	activePolicies := 0
	hasRequiredFactor := false

	for _, policy := range policies {
		if policy.Status == "ACTIVE" {
			activePolicies++

			// Parse settings to check factor enrollment requirements.
			var settings oktaPolicySettings
			if err := json.Unmarshal(policy.Settings, &settings); err == nil {
				for _, factor := range settings.Factors {
					if factor.Enroll.Self == "REQUIRED" {
						hasRequiredFactor = true
					}
				}
			}

			findings = append(findings, evidence.Finding{
				Title:       fmt.Sprintf("MFA Policy Active: %s", policy.Name),
				Description: fmt.Sprintf("MFA enrollment policy %q (ID: %s) is active", policy.Name, policy.ID),
				SeverityID:  0, // informational
			})
		} else {
			findings = append(findings, evidence.Finding{
				Title:       fmt.Sprintf("MFA Policy Inactive: %s", policy.Name),
				Description: fmt.Sprintf("MFA enrollment policy %q (ID: %s) is %s — not enforcing MFA", policy.Name, policy.ID, policy.Status),
				SeverityID:  2, // warning
			})
		}
	}

	// Determine overall status.
	statusID := evidence.StatusEffective
	status := "MFA enrollment policies are active and enforcing"

	if len(policies) == 0 {
		statusID = evidence.StatusIneffective
		status = "No MFA enrollment policies found"
		findings = append(findings, evidence.Finding{
			Title:       "No MFA Policies",
			Description: "No MFA enrollment policies exist in the Okta organization",
			SeverityID:  3, // high
		})
	} else if activePolicies == 0 {
		statusID = evidence.StatusIneffective
		status = "All MFA enrollment policies are inactive"
	} else if !hasRequiredFactor {
		statusID = evidence.StatusIneffective
		status = "No MFA factors are set to required enrollment"
		findings = append(findings, evidence.Finding{
			Title:       "No Required MFA Factors",
			Description: "Active MFA policies exist but no factors are set to REQUIRED enrollment",
			SeverityID:  2,
		})
	}

	// Build raw data.
	rawData := map[string]interface{}{
		"policies":          policies,
		"total_policies":    len(policies),
		"active_policies":   activePolicies,
		"has_required_factor": hasRequiredFactor,
	}
	rawJSON, _ := json.Marshal(rawData)

	ev := evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "mfa.enforcement",
		ClassUID:        1001,
		CategoryUID:     1,
		ActivityID:      1, // Config Check
		Time:            now,
		ConfidenceLevel: evidence.PassiveObservation,
		Metadata: evidence.Metadata{
			Module: evidence.ModuleInfo{
				Name:    "okta.mfa_policy",
				Version: "0.1.0",
				Type:    "collector",
			},
			Source: evidence.SourceInfo{
				System:     "okta",
				APIVersion: "v1",
				Endpoint:   "/api/v1/policies?type=MFA_ENROLL",
			},
			ProcessedTime: now,
		},
		Observables: []evidence.Observable{
			{Type: "resource", Value: "mfa_policy"},
		},
		StatusID: statusID,
		Status:   status,
		RawData:  rawJSON,
		Findings: findings,
	}

	return []evidence.Evidence{ev}, nil
}
