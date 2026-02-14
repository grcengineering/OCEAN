// Package okta provides OCEAN tester modules for active control verification
// against Okta identity management. Testers attempt actions that controls should
// prevent, recording results as evidence with full test transcripts.
package okta

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

// MFABypassTester attempts authentication against Okta without providing
// an MFA token to verify that MFA enforcement is working. This is a safe,
// read-only probe that makes no state changes -- it only observes whether
// the authentication attempt is properly blocked or requires MFA.
type MFABypassTester struct{}

// Compile-time interface check.
var _ module.Tester = (*MFABypassTester)(nil)

func (m *MFABypassTester) ID() string            { return "okta.mfa_bypass" }
func (m *MFABypassTester) Name() string          { return "Okta MFA Bypass Tester" }
func (m *MFABypassTester) Version() string       { return "0.1.0" }
func (m *MFABypassTester) SourceSystem() string  { return "okta" }
func (m *MFABypassTester) EvidenceTypes() []int  { return []int{1001} }

func (m *MFABypassTester) CredentialRequirements() []module.CredentialReq {
	return []module.CredentialReq{
		{
			Name:        "OKTA_API_TOKEN",
			Type:        "api_token",
			Description: "Okta API token (for pre-flight API reachability check)",
			Required:    true,
		},
		{
			Name:        "OKTA_DOMAIN",
			Type:        "domain",
			Description: "Okta organization domain (e.g., example.okta.com)",
			Required:    true,
		},
		{
			Name:        "OKTA_TEST_USER",
			Type:        "username",
			Description: "Test user username for MFA bypass attempt",
			Required:    true,
		},
		{
			Name:        "OKTA_TEST_PASSWORD",
			Type:        "password",
			Description: "Test user password for MFA bypass attempt",
			Required:    true,
		},
	}
}

func (m *MFABypassTester) SafetyClass() module.SafetyClassification {
	return module.SafetyClassSafe
}

func (m *MFABypassTester) EnvironmentScope() module.EnvironmentScope {
	return module.ScopeProduction
}

func (m *MFABypassTester) PreFlightChecks() []string {
	return []string{
		"verify Okta API reachable",
		"verify test credentials configured",
	}
}

func (m *MFABypassTester) CleanupProcedures() []string {
	// Safe classification -- no state changes, no cleanup needed.
	return []string{}
}

// oktaAuthnRequest is the request body for POST /api/v1/authn.
type oktaAuthnRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// oktaAuthnResponse represents the relevant fields from the Okta authn response.
type oktaAuthnResponse struct {
	Status       string          `json:"status"`
	ErrorCode    string          `json:"errorCode,omitempty"`
	ErrorSummary string          `json:"errorSummary,omitempty"`
	SessionToken string          `json:"sessionToken,omitempty"`
	Embedded     json.RawMessage `json:"_embedded,omitempty"`
}

// Test attempts to authenticate against Okta without providing an MFA token.
// It records the authentication response in the test transcript and determines
// whether the MFA control is effective based on the outcome.
func (m *MFABypassTester) Test(ctx context.Context, config map[string]string) ([]evidence.Evidence, error) {
	// Validate required configuration.
	token := config["OKTA_API_TOKEN"]
	domain := config["OKTA_DOMAIN"]
	testUser := config["OKTA_TEST_USER"]
	testPassword := config["OKTA_TEST_PASSWORD"]

	if token == "" || domain == "" {
		return nil, fmt.Errorf("OKTA_API_TOKEN and OKTA_DOMAIN are required")
	}
	if testUser == "" || testPassword == "" {
		return nil, fmt.Errorf("OKTA_TEST_USER and OKTA_TEST_PASSWORD are required for MFA bypass testing")
	}

	insecure := config["OKTA_INSECURE"] == "true"
	scheme := "https"
	if insecure {
		scheme = "http"
	}

	now := time.Now().UTC()
	recorder := evidence.NewTranscriptRecorder()

	// Record the authentication attempt.
	recorder.RecordAction("initiate authentication without MFA token", map[string]string{
		"target":   domain,
		"method":   "primary_auth_only",
		"user":     testUser,
		"endpoint": "/api/v1/authn",
	})

	// Build the authentication request body (credentials only, no MFA token).
	authnReq := oktaAuthnRequest{
		Username: testUser,
		Password: testPassword,
	}
	reqBody, err := json.Marshal(authnReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authn request: %w", err)
	}

	url := fmt.Sprintf("%s://%s/api/v1/authn", scheme, domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create authn request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "OCEAN/0.1.0")

	recorder.RecordAction("submit credentials without MFA token", map[string]string{
		"credentials": "redacted",
		"mfa_token":   "none",
	})

	// Execute the authentication request.
	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authn request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read authn response: %w", err)
	}

	// Parse the response.
	var authnResp oktaAuthnResponse
	_ = json.Unmarshal(respBody, &authnResp)

	// Determine control effectiveness based on the response.
	statusID := evidence.StatusEffective
	status := "MFA bypass attempt was correctly blocked"
	bypassBlocked := true

	switch {
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
		// 401/403: Authentication rejected outright -- MFA enforcement is working.
		recorder.RecordObservation(
			fmt.Sprintf("authentication rejected with HTTP %d", resp.StatusCode),
			true,
		)
		recorder.RecordObservation("MFA bypass attempt blocked", true)

	case authnResp.Status == "MFA_REQUIRED":
		// Okta responded with MFA_REQUIRED -- control is effective.
		recorder.RecordObservation("Okta returned MFA_REQUIRED status", true)
		recorder.RecordObservation("MFA challenge required before session can be established", true)

	case authnResp.Status == "SUCCESS":
		// Authentication succeeded without MFA -- control is INEFFECTIVE.
		statusID = evidence.StatusIneffective
		status = "MFA bypass succeeded -- authentication completed without MFA"
		bypassBlocked = false
		recorder.RecordObservation("authentication succeeded without MFA challenge", false)
		recorder.RecordObservation(
			fmt.Sprintf("session token issued: %v", authnResp.SessionToken != ""),
			false,
		)

	default:
		// Other status (e.g., LOCKED_OUT, PASSWORD_EXPIRED) -- still effective.
		recorder.RecordObservation(
			fmt.Sprintf("Okta returned status %q (HTTP %d)", authnResp.Status, resp.StatusCode),
			true,
		)
		recorder.RecordObservation("authentication did not succeed without MFA", true)
	}

	transcript := recorder.Finalize()

	// Build raw data.
	rawData := map[string]interface{}{
		"test_scenario": "mfa_bypass_attempt",
		"target_system": domain,
		"test_result":   "blocked",
		"http_status":   resp.StatusCode,
		"authn_status":  authnResp.Status,
		"bypass_blocked": bypassBlocked,
	}
	if !bypassBlocked {
		rawData["test_result"] = "bypassed"
	}
	rawJSON, _ := json.Marshal(rawData)

	safetyClass := string(module.SafetyClassSafe)

	// Build findings.
	var findings []evidence.Finding
	if bypassBlocked {
		findings = append(findings, evidence.Finding{
			Title:       "MFA Bypass Blocked",
			Description: fmt.Sprintf("Authentication attempt without MFA was blocked (HTTP %d, status: %s)", resp.StatusCode, authnResp.Status),
			SeverityID:  0, // informational
		})
	} else {
		findings = append(findings, evidence.Finding{
			Title:       "MFA Bypass Succeeded",
			Description: "Authentication completed without MFA challenge -- MFA enforcement is not working",
			SeverityID:  3, // high severity
		})
	}

	ev := evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "mfa.enforcement",
		ClassUID:        1001,
		CategoryUID:     1,
		ActivityID:      2, // Active Test
		Time:            now,
		ConfidenceLevel: evidence.ActiveVerification,
		Metadata: evidence.Metadata{
			Module: evidence.ModuleInfo{
				Name:    "okta.mfa_bypass",
				Version: "0.1.0",
				Type:    "tester",
			},
			Source: evidence.SourceInfo{
				System:     "okta",
				APIVersion: "v1",
				Endpoint:   "/api/v1/authn",
			},
			ProcessedTime:        now,
			SafetyClassification: &safetyClass,
		},
		Observables: []evidence.Observable{
			{Type: "resource", Value: "mfa_policy"},
			{Type: "user", Value: testUser},
		},
		StatusID:       statusID,
		Status:         status,
		RawData:        rawJSON,
		Findings:       findings,
		TestTranscript: transcript,
	}

	return []evidence.Evidence{ev}, nil
}
