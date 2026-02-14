// Package github provides OCEAN testers for GitHub's REST API v3.
// It performs active control verification by attempting actions that
// security controls should prevent, such as pushing secrets to
// repositories with push protection enabled.
package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

const (
	// defaultBaseURL is the GitHub REST API v3 base URL.
	defaultBaseURL = "https://api.github.com"

	// defaultAPIVersion is the GitHub API version used in Accept headers.
	defaultAPIVersion = "2022-11-28"

	// testFilePath is the path where the test secret file is created.
	testFilePath = ".ocean-test/secret-push-test.txt"

	// testSecret is a well-known test secret pattern that GitHub's push
	// protection should detect. It uses the GitHub PAT format.
	testSecret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01"

	// testCommitMessage is the commit message used when creating the test file.
	testCommitMessage = "ocean: secret push protection test (will be cleaned up)"
)

// SecretPushTester attempts to push a file containing a known test
// secret string to a GitHub repository via the Contents API. It
// records whether GitHub's push protection blocks the attempt. This
// is an active control verification test classified as "observable"
// because it creates audit trail entries in GitHub but does not
// modify production state when push protection is working correctly.
type SecretPushTester struct{}

// Compile-time interface check.
var _ module.Tester = (*SecretPushTester)(nil)

func (t *SecretPushTester) ID() string           { return "github.secret_push" }
func (t *SecretPushTester) Name() string          { return "GitHub Secret Push Protection Test" }
func (t *SecretPushTester) Version() string       { return "0.1.0" }
func (t *SecretPushTester) SourceSystem() string  { return "github" }
func (t *SecretPushTester) EvidenceTypes() []int  { return []int{1003} }

func (t *SecretPushTester) CredentialRequirements() []module.CredentialReq {
	return []module.CredentialReq{
		{
			Name:        "GITHUB_TOKEN",
			Type:        "api_token",
			Description: "GitHub personal access token with repo scope for creating and deleting files via Contents API",
			Required:    true,
		},
		{
			Name:        "GITHUB_OWNER",
			Type:        "config",
			Description: "GitHub repository owner (user or organization)",
			Required:    true,
		},
		{
			Name:        "GITHUB_REPO",
			Type:        "config",
			Description: "GitHub repository name (must be a test/staging repository)",
			Required:    true,
		},
	}
}

func (t *SecretPushTester) SafetyClass() module.SafetyClassification {
	return module.SafetyClassObservable
}

func (t *SecretPushTester) EnvironmentScope() module.EnvironmentScope {
	return module.ScopeStaging
}

func (t *SecretPushTester) PreFlightChecks() []string {
	return []string{
		"verify GitHub token has write access",
		"verify repository is a test/staging repository",
		"document: this test creates audit trail entries in GitHub",
	}
}

func (t *SecretPushTester) CleanupProcedures() []string {
	return []string{
		"delete test file if created",
	}
}

// ghClient wraps net/http for GitHub API calls used by the tester.
type ghClient struct {
	httpClient *http.Client
	baseURL    string
	token      string
}

// newGHClient creates a GitHub API client from a module config map.
func newGHClient(config map[string]string) (*ghClient, error) {
	token := config["GITHUB_TOKEN"]
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN is required")
	}

	baseURL := config["GITHUB_API_URL"]
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	return &ghClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    baseURL,
		token:      token,
	}, nil
}

// doRequest performs an authenticated request to the GitHub API.
func (c *ghClient) doRequest(method, path string, body io.Reader) (json.RawMessage, int, error) {
	url := c.baseURL + path

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, 0, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-GitHub-Api-Version", defaultAPIVersion)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("executing request to %s: %w", path, err)
	}
	defer resp.Body.Close()

	// Check rate limiting.
	if remaining := resp.Header.Get("X-RateLimit-Remaining"); remaining != "" {
		if rem, err := strconv.Atoi(remaining); err == nil && rem == 0 {
			resetStr := resp.Header.Get("X-RateLimit-Reset")
			resetTime := "unknown"
			if resetStr != "" {
				if ts, err := strconv.ParseInt(resetStr, 10, 64); err == nil {
					resetTime = time.Unix(ts, 0).UTC().Format(time.RFC3339)
				}
			}
			return nil, resp.StatusCode, fmt.Errorf("GitHub API rate limit exceeded, resets at %s", resetTime)
		}
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading response body: %w", err)
	}

	return json.RawMessage(respBody), resp.StatusCode, nil
}

// contentsCreateRequest is the payload for creating a file via the Contents API.
type contentsCreateRequest struct {
	Message string `json:"message"`
	Content string `json:"content"`
}

// contentsDeleteRequest is the payload for deleting a file via the Contents API.
type contentsDeleteRequest struct {
	Message string `json:"message"`
	SHA     string `json:"sha"`
}

// contentsResponse represents relevant fields from the Contents API response.
type contentsResponse struct {
	Content struct {
		SHA string `json:"sha"`
	} `json:"content"`
}

// Test attempts to push a file containing a test secret to the configured
// GitHub repository. It records whether push protection blocks the attempt,
// and cleans up any test artifacts that were created.
func (t *SecretPushTester) Test(ctx context.Context, config map[string]string) ([]evidence.Evidence, error) {
	_ = ctx // Reserved for future cancellation support.

	c, err := newGHClient(config)
	if err != nil {
		return nil, fmt.Errorf("creating GitHub client: %w", err)
	}

	owner := config["GITHUB_OWNER"]
	if owner == "" {
		return nil, fmt.Errorf("GITHUB_OWNER is required")
	}

	repo := config["GITHUB_REPO"]
	if repo == "" {
		return nil, fmt.Errorf("GITHUB_REPO is required")
	}

	now := time.Now().UTC()
	recorder := evidence.NewTranscriptRecorder()
	safetyClass := string(module.SafetyClassObservable)
	endpoint := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, testFilePath)

	// Record the test action.
	recorder.RecordAction("attempt to create file containing test secret via Contents API", map[string]string{
		"owner":    owner,
		"repo":     repo,
		"path":     testFilePath,
		"secret":   "ghp_ABCDEFGHIJ... (GitHub PAT format test string)",
		"endpoint": endpoint,
	})

	// Encode the test secret content as base64.
	fileContent := fmt.Sprintf("# OCEAN Secret Push Protection Test\n# This file is created by the ocean github.secret_push tester.\n# It will be automatically cleaned up.\n\nTEST_TOKEN=%s\n", testSecret)
	encodedContent := base64.StdEncoding.EncodeToString([]byte(fileContent))

	createPayload := contentsCreateRequest{
		Message: testCommitMessage,
		Content: encodedContent,
	}
	payloadBytes, err := json.Marshal(createPayload)
	if err != nil {
		return nil, fmt.Errorf("marshaling create payload: %w", err)
	}

	// Attempt to create the file.
	respBody, statusCode, err := c.doRequest(http.MethodPut, endpoint, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("creating test file: %w", err)
	}

	var statusID evidence.StatusID
	var statusMsg string
	var findings []evidence.Finding
	var fileSHA string

	// Evaluate whether push protection blocked the secret.
	switch {
	case statusCode == 409:
		// 409 Conflict indicates push protection blocked the push.
		recorder.RecordObservation("push protection blocked the secret push with HTTP 409", true)
		statusID = evidence.StatusEffective
		statusMsg = "GitHub push protection correctly blocked a test secret push"
		findings = append(findings, evidence.Finding{
			Title:       "Secret Push Blocked",
			Description: fmt.Sprintf("GitHub push protection blocked an attempt to push a file containing a test secret (GitHub PAT format) to %s/%s. The control is operating effectively.", owner, repo),
			SeverityID:  0, // informational
		})

	case statusCode == 422:
		// 422 Unprocessable Entity can also indicate push protection.
		recorder.RecordObservation("push protection blocked the secret push with HTTP 422", true)
		statusID = evidence.StatusEffective
		statusMsg = "GitHub push protection correctly blocked a test secret push"
		findings = append(findings, evidence.Finding{
			Title:       "Secret Push Blocked",
			Description: fmt.Sprintf("GitHub push protection blocked an attempt to push a file containing a test secret to %s/%s with HTTP 422. The control is operating effectively.", owner, repo),
			SeverityID:  0, // informational
		})

	case statusCode == 201:
		// 201 Created means the push succeeded -- push protection is NOT blocking secrets.
		recorder.RecordObservation("secret push was NOT blocked, file was created successfully", false)
		statusID = evidence.StatusIneffective
		statusMsg = fmt.Sprintf("GitHub push protection did NOT block a test secret push to %s/%s", owner, repo)
		findings = append(findings, evidence.Finding{
			Title:       "Secret Push Not Blocked",
			Description: fmt.Sprintf("A file containing a test secret (GitHub PAT format) was successfully pushed to %s/%s. Push protection is either disabled or not detecting this secret pattern. The test file will be cleaned up.", owner, repo),
			SeverityID:  4, // high
		})

		// Extract the file SHA for cleanup.
		var createResp contentsResponse
		if err := json.Unmarshal(respBody, &createResp); err == nil {
			fileSHA = createResp.Content.SHA
		}

	default:
		// Unexpected status code.
		recorder.RecordObservation(fmt.Sprintf("unexpected HTTP status %d from Contents API", statusCode), false)
		statusID = evidence.StatusUnknown
		statusMsg = fmt.Sprintf("Unexpected response (HTTP %d) when testing push protection on %s/%s", statusCode, owner, repo)
		findings = append(findings, evidence.Finding{
			Title:       "Unexpected API Response",
			Description: fmt.Sprintf("The GitHub Contents API returned HTTP %d when attempting to push a test secret. This may indicate insufficient permissions, a nonexistent repository, or an API error.", statusCode),
			SeverityID:  2, // low
		})
	}

	// Cleanup: delete the test file if it was created.
	if fileSHA != "" {
		recorder.RecordAction("delete test file created during secret push test", map[string]string{
			"path": testFilePath,
			"sha":  fileSHA,
		})

		deletePayload := contentsDeleteRequest{
			Message: "ocean: clean up secret push protection test file",
			SHA:     fileSHA,
		}
		deleteBytes, _ := json.Marshal(deletePayload)
		_, deleteStatus, deleteErr := c.doRequest(http.MethodDelete, endpoint, bytes.NewReader(deleteBytes))

		if deleteErr != nil || (deleteStatus != 200 && deleteStatus != 204) {
			recorder.RecordCleanup("delete test file if created", false)
			findings = append(findings, evidence.Finding{
				Title:       "Cleanup Failed",
				Description: fmt.Sprintf("Failed to delete the test file %s from %s/%s. Manual cleanup may be required.", testFilePath, owner, repo),
				SeverityID:  2, // low
			})
		} else {
			recorder.RecordCleanup("delete test file if created", true)
		}
	} else {
		// No file was created, so cleanup is a no-op success.
		recorder.RecordCleanup("delete test file if created", true)
	}

	transcript := recorder.Finalize()

	// Build raw data capturing the full test context.
	rawData := map[string]interface{}{
		"test_scenario":   "secret_push_protection",
		"target_repo":     fmt.Sprintf("%s/%s", owner, repo),
		"test_file_path":  testFilePath,
		"secret_pattern":  "github_pat_format",
		"http_status":     statusCode,
		"push_blocked":    statusID == evidence.StatusEffective,
		"file_created":    fileSHA != "",
		"cleanup_needed":  fileSHA != "",
	}
	rawJSON, _ := json.Marshal(rawData)

	ev := evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "scm.secret_push_protection",
		ClassUID:        1003,
		CategoryUID:     2,
		ActivityID:      2, // Active Test
		Time:            now,
		ConfidenceLevel: evidence.ActiveVerification,
		Metadata: evidence.Metadata{
			Module: evidence.ModuleInfo{
				Name:    "github.secret_push",
				Version: "0.1.0",
				Type:    "tester",
			},
			Source: evidence.SourceInfo{
				System:     "github",
				APIVersion: "v3",
				Endpoint:   endpoint,
			},
			ProcessedTime:        now,
			SafetyClassification: &safetyClass,
		},
		Observables: []evidence.Observable{
			{Type: "resource", Value: fmt.Sprintf("%s/%s:%s", owner, repo, testFilePath)},
			{Type: "domain", Value: "github.com"},
		},
		StatusID:       statusID,
		Status:         statusMsg,
		RawData:        rawJSON,
		Findings:       findings,
		TestTranscript: transcript,
	}

	return []evidence.Evidence{ev}, nil
}
