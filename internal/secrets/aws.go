package secrets

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AWSProvider retrieves secrets from AWS Secrets Manager using the
// HTTP API with AWS Signature V4 signing. It uses only the standard
// library -- no AWS SDK dependency.
type AWSProvider struct {
	region          string
	accessKeyID     string
	secretAccessKey string
	client          *http.Client
	// endpoint is overridable for testing.
	endpoint string
}

// NewAWSProvider creates an AWSProvider for the given region and credentials.
func NewAWSProvider(region, accessKeyID, secretAccessKey string) *AWSProvider {
	return &AWSProvider{
		region:          region,
		accessKeyID:     accessKeyID,
		secretAccessKey: secretAccessKey,
		client:          &http.Client{},
		endpoint:        fmt.Sprintf("https://secretsmanager.%s.amazonaws.com", region),
	}
}

// Get retrieves a secret by name from AWS Secrets Manager.
func (p *AWSProvider) Get(name string) (string, error) {
	payload := fmt.Sprintf(`{"SecretId":%q}`, name)

	req, err := http.NewRequest(http.MethodPost, p.endpoint, strings.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("aws: failed to create request: %w", err)
	}

	now := time.Now().UTC()
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))

	p.signRequest(req, []byte(payload), now)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("aws: connection failed for secret %q: %w", name, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("aws: failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Try to extract AWS error details.
		var awsErr struct {
			Type    string `json:"__type"`
			Message string `json:"Message"`
		}
		if json.Unmarshal(body, &awsErr) == nil && awsErr.Message != "" {
			return "", fmt.Errorf("aws: %s: %s", awsErr.Type, awsErr.Message)
		}
		return "", fmt.Errorf("aws: request failed for secret %q (HTTP %d): %s",
			name, resp.StatusCode, string(body))
	}

	var result struct {
		SecretString *string `json:"SecretString"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("aws: failed to parse response for secret %q: %w", name, err)
	}
	if result.SecretString == nil {
		return "", fmt.Errorf("aws: secret %q does not contain a SecretString (may be binary)", name)
	}

	return *result.SecretString, nil
}

// signRequest applies AWS Signature V4 to the HTTP request.
// This is a minimal implementation covering the Secrets Manager use case.
func (p *AWSProvider) signRequest(req *http.Request, payload []byte, now time.Time) {
	const service = "secretsmanager"

	datestamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", datestamp, p.region, service)

	// ---- Task 1: Canonical Request ----
	payloadHash := sha256Hex(payload)

	signedHeaders := "content-type;host;x-amz-date;x-amz-target"
	canonicalHeaders := fmt.Sprintf("content-type:%s\nhost:%s\nx-amz-date:%s\nx-amz-target:%s\n",
		req.Header.Get("Content-Type"),
		req.URL.Host,
		amzDate,
		req.Header.Get("X-Amz-Target"),
	)

	canonicalRequest := strings.Join([]string{
		req.Method,
		"/",
		"", // canonical query string (empty)
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	// ---- Task 2: String to Sign ----
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	// ---- Task 3: Signing Key ----
	signingKey := deriveSigningKey(p.secretAccessKey, datestamp, p.region, service)

	// ---- Task 4: Signature ----
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	// ---- Task 5: Authorization Header ----
	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		p.accessKeyID, credentialScope, signedHeaders, signature)

	req.Header.Set("Authorization", authHeader)
}

// deriveSigningKey produces the AWS Sig V4 signing key:
//
//	HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")
func deriveSigningKey(secret, datestamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(datestamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
