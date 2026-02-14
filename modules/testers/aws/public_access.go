// Package aws provides real-world AWS testers for OCEAN. This package
// includes active control verification modules that test AWS security
// controls by safely probing for misconfigurations.
package aws

import (
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

// PublicAccessTester verifies that an S3 bucket is not publicly accessible
// by performing an unauthenticated HTTP GET against the bucket URL. This
// is a safe (read-only) test that requires no AWS credentials -- it simply
// checks whether an anonymous request is blocked (403 Forbidden) or
// allowed (200 OK).
//
// Configuration:
//   - AWS_TEST_BUCKET: The S3 bucket URL to test (e.g., "https://my-bucket.s3.amazonaws.com/")
type PublicAccessTester struct{}

// Compile-time interface check.
var _ module.Tester = (*PublicAccessTester)(nil)

func (t *PublicAccessTester) ID() string           { return "aws.s3_public_access" }
func (t *PublicAccessTester) Name() string         { return "AWS S3 Public Access Tester" }
func (t *PublicAccessTester) Version() string      { return "0.1.0" }
func (t *PublicAccessTester) SourceSystem() string { return "aws" }
func (t *PublicAccessTester) EvidenceTypes() []int { return []int{1002} }

func (t *PublicAccessTester) CredentialRequirements() []module.CredentialReq {
	return []module.CredentialReq{
		{
			Name:        "AWS_TEST_BUCKET",
			Type:        "config",
			Description: "S3 bucket URL to test for public access (e.g., https://my-bucket.s3.amazonaws.com/)",
			Required:    true,
		},
	}
}

func (t *PublicAccessTester) SafetyClass() module.SafetyClassification {
	return module.SafetyClassSafe
}

func (t *PublicAccessTester) EnvironmentScope() module.EnvironmentScope {
	return module.ScopeProduction
}

func (t *PublicAccessTester) PreFlightChecks() []string {
	return []string{"verify test bucket URL configured"}
}

func (t *PublicAccessTester) CleanupProcedures() []string {
	// Safe test with no state changes -- no cleanup needed.
	return nil
}

// Test performs an unauthenticated HTTP GET to the configured S3 bucket
// URL and records whether the request is blocked (403) or allowed (200).
// A blocked response means the control is effective; an allowed response
// means the bucket is publicly accessible (control ineffective).
func (t *PublicAccessTester) Test(ctx context.Context, config map[string]string) ([]evidence.Evidence, error) {
	bucketURL := config["AWS_TEST_BUCKET"]
	if bucketURL == "" {
		return nil, fmt.Errorf("AWS_TEST_BUCKET is required: specify the S3 bucket URL to test")
	}

	now := time.Now().UTC()
	recorder := evidence.NewTranscriptRecorder()

	// Record pre-flight check.
	recorder.RecordAction("pre-flight: verify test bucket URL configured", map[string]string{
		"bucket_url": bucketURL,
	})
	recorder.RecordObservation("test bucket URL is configured", true)

	// Perform unauthenticated HTTP GET.
	recorder.RecordAction("attempt unauthenticated HTTP GET to S3 bucket", map[string]string{
		"method": "GET",
		"url":    bucketURL,
		"auth":   "none (anonymous)",
	})

	httpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bucketURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		// Network error -- record it but still produce evidence.
		recorder.RecordObservation(fmt.Sprintf("request failed with error: %v", err), false)
		transcript := recorder.Finalize()

		rawData := map[string]interface{}{
			"test_scenario":  "s3_public_access_check",
			"target_bucket":  bucketURL,
			"test_result":    "error",
			"error":          err.Error(),
		}
		rawJSON, _ := json.Marshal(rawData)

		safetyClass := string(module.SafetyClassSafe)
		ev := evidence.Evidence{
			ID:              uuid.New(),
			ControlID:       "s3.public_access",
			ClassUID:        1002,
			CategoryUID:     3,
			ActivityID:      2, // Active Test
			Time:            now,
			ConfidenceLevel: evidence.ActiveVerification,
			Metadata: evidence.Metadata{
				Module: evidence.ModuleInfo{
					Name:    t.ID(),
					Version: t.Version(),
					Type:    "tester",
				},
				Source: evidence.SourceInfo{
					System:     "aws",
					APIVersion: "s3",
					Endpoint:   bucketURL,
				},
				ProcessedTime:        now,
				SafetyClassification: &safetyClass,
			},
			Observables: []evidence.Observable{
				{Type: "resource", Value: bucketURL},
			},
			StatusID: evidence.StatusUnknown,
			Status:   fmt.Sprintf("Could not reach bucket: %v", err),
			RawData:  rawJSON,
			Findings: []evidence.Finding{
				{
					Title:       "S3 Public Access Check Failed",
					Description: fmt.Sprintf("Could not connect to %s: %v", bucketURL, err),
					SeverityID:  1, // low -- inconclusive
				},
			},
			TestTranscript: transcript,
		}

		return []evidence.Evidence{ev}, nil
	}
	defer resp.Body.Close()

	// Read a limited amount of the response body for evidence.
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	bodySnippet := string(bodyBytes)
	if len(bodySnippet) > 512 {
		bodySnippet = bodySnippet[:512] + "...(truncated)"
	}

	// Evaluate the result.
	var statusID evidence.StatusID
	var statusText string
	var findings []evidence.Finding
	var testResult string

	switch {
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound:
		// 403 Forbidden or 404 Not Found = access blocked, control effective.
		testResult = "blocked"
		statusID = evidence.StatusEffective
		statusText = fmt.Sprintf("S3 bucket access blocked with HTTP %d", resp.StatusCode)
		recorder.RecordObservation(fmt.Sprintf("unauthenticated request returned HTTP %d (access denied)", resp.StatusCode), true)
		findings = append(findings, evidence.Finding{
			Title:       "S3 Public Access Blocked",
			Description: fmt.Sprintf("Unauthenticated GET to %s returned HTTP %d, confirming public access is denied", bucketURL, resp.StatusCode),
			SeverityID:  0, // informational
		})

	case resp.StatusCode == http.StatusOK:
		// 200 OK = publicly accessible, control ineffective.
		testResult = "allowed"
		statusID = evidence.StatusIneffective
		statusText = "S3 bucket is publicly accessible"
		recorder.RecordObservation("unauthenticated request returned HTTP 200 (publicly accessible)", false)
		findings = append(findings, evidence.Finding{
			Title:       "S3 Bucket Publicly Accessible",
			Description: fmt.Sprintf("Unauthenticated GET to %s returned HTTP 200, indicating the bucket is publicly accessible", bucketURL),
			SeverityID:  4, // critical
		})

	default:
		// Unexpected status code -- record but mark as unknown.
		testResult = fmt.Sprintf("unexpected_http_%d", resp.StatusCode)
		statusID = evidence.StatusUnknown
		statusText = fmt.Sprintf("S3 bucket returned unexpected HTTP %d", resp.StatusCode)
		recorder.RecordObservation(fmt.Sprintf("unauthenticated request returned unexpected HTTP %d", resp.StatusCode), false)
		findings = append(findings, evidence.Finding{
			Title:       "Unexpected S3 Response",
			Description: fmt.Sprintf("Unauthenticated GET to %s returned HTTP %d which could not be classified", bucketURL, resp.StatusCode),
			SeverityID:  2, // medium
		})
	}

	// No cleanup needed for safe read-only test.
	recorder.RecordCleanup("no cleanup required (safe read-only test)", true)

	transcript := recorder.Finalize()

	rawData := map[string]interface{}{
		"test_scenario":    "s3_public_access_check",
		"target_bucket":    bucketURL,
		"test_result":      testResult,
		"http_status":      resp.StatusCode,
		"response_snippet": bodySnippet,
	}
	rawJSON, _ := json.Marshal(rawData)

	safetyClass := string(module.SafetyClassSafe)

	ev := evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "s3.public_access",
		ClassUID:        1002,
		CategoryUID:     3,
		ActivityID:      2, // Active Test
		Time:            now,
		ConfidenceLevel: evidence.ActiveVerification,
		Metadata: evidence.Metadata{
			Module: evidence.ModuleInfo{
				Name:    t.ID(),
				Version: t.Version(),
				Type:    "tester",
			},
			Source: evidence.SourceInfo{
				System:     "aws",
				APIVersion: "s3",
				Endpoint:   bucketURL,
			},
			ProcessedTime:        now,
			SafetyClassification: &safetyClass,
		},
		Observables: []evidence.Observable{
			{Type: "resource", Value: bucketURL},
		},
		StatusID:       statusID,
		Status:         statusText,
		RawData:        rawJSON,
		Findings:       findings,
		TestTranscript: transcript,
	}

	return []evidence.Evidence{ev}, nil
}
