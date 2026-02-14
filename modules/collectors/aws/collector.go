// Package aws provides real-world AWS collectors for OCEAN. It includes a
// minimal AWS API client that signs requests using AWS Signature V4 (built
// entirely on net/http and crypto/hmac) and collectors that query IAM and
// other AWS services to produce evidence records.
package aws

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/grcengineering/ocean/internal/module"
)

// Default region used when AWS_REGION is not provided in config.
const defaultRegion = "us-east-1"

// RegisterAll registers all AWS collectors with the given registry.
func RegisterAll(reg *module.Registry) {
	reg.RegisterCollector(&IAMCollector{})
}

// ----- AWS API Client -----

// awsClient is a minimal AWS API client that signs requests with Signature
// Version 4 using only the standard library. It supports simple rate limiting
// with exponential backoff on throttling responses.
type awsClient struct {
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	region          string
	httpClient      *http.Client
}

// newAWSClient creates an awsClient from a module config map. It reads
// AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN (optional),
// and AWS_REGION (defaults to us-east-1).
func newAWSClient(config map[string]string) (*awsClient, error) {
	accessKey := config["AWS_ACCESS_KEY_ID"]
	if accessKey == "" {
		return nil, fmt.Errorf("AWS_ACCESS_KEY_ID is required")
	}

	secretKey := config["AWS_SECRET_ACCESS_KEY"]
	if secretKey == "" {
		return nil, fmt.Errorf("AWS_SECRET_ACCESS_KEY is required")
	}

	region := config["AWS_REGION"]
	if region == "" {
		region = defaultRegion
	}

	return &awsClient{
		accessKeyID:     accessKey,
		secretAccessKey: secretKey,
		sessionToken:    config["AWS_SESSION_TOKEN"],
		region:          region,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// awsErrorResponse represents an AWS XML error response body.
type awsErrorResponse struct {
	XMLName   xml.Name `xml:"ErrorResponse"`
	Error     awsError `xml:"Error"`
	RequestID string   `xml:"RequestId"`
}

// awsError holds the code and message from an AWS error.
type awsError struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// maxRetries is the maximum number of retry attempts for throttled requests.
const maxRetries = 3

// doRequest signs and executes an AWS API request with retry logic for
// throttling (HTTP 429 and 503). It returns the response body bytes on
// success or a descriptive error on failure.
func (c *awsClient) doRequest(ctx context.Context, method, serviceEndpoint string, params url.Values, service string) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 1s, 2s, 4s
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		body, err := c.doSingleRequest(ctx, method, serviceEndpoint, params, service)
		if err == nil {
			return body, nil
		}

		// Retry only on throttle errors.
		if isThrottleError(err) {
			lastErr = err
			continue
		}

		return nil, err
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// throttleError is returned when AWS responds with a throttling status code.
type throttleError struct {
	msg string
}

func (e *throttleError) Error() string { return e.msg }

// isThrottleError checks if an error is a throttle error.
func isThrottleError(err error) bool {
	_, ok := err.(*throttleError)
	return ok
}

// doSingleRequest signs and sends a single HTTP request to an AWS service
// endpoint. It parses error responses and returns a throttleError for
// retryable status codes.
func (c *awsClient) doSingleRequest(ctx context.Context, method, serviceEndpoint string, params url.Values, service string) ([]byte, error) {
	// Build the request URL with query parameters.
	reqURL := serviceEndpoint
	body := ""
	var req *http.Request
	var err error

	if method == http.MethodGet {
		if len(params) > 0 {
			reqURL = serviceEndpoint + "?" + params.Encode()
		}
		req, err = http.NewRequestWithContext(ctx, method, reqURL, nil)
	} else {
		body = params.Encode()
		req, err = http.NewRequestWithContext(ctx, method, serviceEndpoint, strings.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Sign the request with SigV4.
	c.signV4(req, service, body)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	// Handle error status codes.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		return nil, &throttleError{msg: fmt.Sprintf("throttled: HTTP %d", resp.StatusCode)}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var awsErr awsErrorResponse
		if xmlErr := xml.Unmarshal(respBody, &awsErr); xmlErr == nil {
			return nil, fmt.Errorf("AWS API error (%s): %s", awsErr.Error.Code, awsErr.Error.Message)
		}
		return nil, fmt.Errorf("AWS API error: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// ----- AWS Signature V4 Implementation -----

// signV4 signs an HTTP request using AWS Signature Version 4. It uses
// crypto/hmac and crypto/sha256 from the standard library.
func (c *awsClient) signV4(req *http.Request, service, body string) {
	now := time.Now().UTC()
	datestamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	// Set required headers.
	req.Header.Set("X-Amz-Date", amzDate)
	if req.Header.Get("Host") == "" {
		req.Header.Set("Host", req.URL.Host)
	}
	if c.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.sessionToken)
	}

	// Step 1: Create canonical request.
	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalQueryString := req.URL.Query().Encode()

	// Build signed headers (sorted, lowercase).
	signedHeaderKeys := make([]string, 0, len(req.Header)+1)
	headerMap := make(map[string]string)

	// Always include host.
	headerMap["host"] = req.URL.Host
	signedHeaderKeys = append(signedHeaderKeys, "host")

	for key := range req.Header {
		lowerKey := strings.ToLower(key)
		if lowerKey == "host" {
			continue // already added
		}
		headerMap[lowerKey] = strings.TrimSpace(req.Header.Get(key))
		signedHeaderKeys = append(signedHeaderKeys, lowerKey)
	}
	sort.Strings(signedHeaderKeys)

	var canonicalHeaders strings.Builder
	for _, key := range signedHeaderKeys {
		canonicalHeaders.WriteString(key)
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(headerMap[key])
		canonicalHeaders.WriteString("\n")
	}

	signedHeaders := strings.Join(signedHeaderKeys, ";")
	payloadHash := sha256Hex(body)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	// Step 2: Create string to sign.
	credentialScope := strings.Join([]string{datestamp, c.region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex(canonicalRequest),
	}, "\n")

	// Step 3: Calculate signature.
	signingKey := deriveSigningKey(c.secretAccessKey, datestamp, c.region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	// Step 4: Add authorization header.
	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.accessKeyID, credentialScope, signedHeaders, signature,
	)
	req.Header.Set("Authorization", authHeader)
}

// deriveSigningKey derives the SigV4 signing key from the secret key,
// date, region, and service using the standard HMAC chain:
// kDate -> kRegion -> kService -> kSigning
func deriveSigningKey(secretKey, datestamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(datestamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

// hmacSHA256 computes the HMAC-SHA256 of data using the provided key.
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// sha256Hex returns the lowercase hex-encoded SHA-256 hash of s.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
