package aws

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

// iamEndpoint is the AWS IAM API endpoint. IAM is a global service and
// always uses us-east-1 regardless of the configured region.
const iamEndpoint = "https://iam.amazonaws.com/"

// iamService is the AWS service name used for SigV4 signing.
const iamService = "iam"

// iamAPIVersion is the IAM API version string.
const iamAPIVersion = "2010-05-08"

// accessKeyMaxAgeDays is the maximum age (in days) before an access key
// is considered stale and flagged as a finding.
const accessKeyMaxAgeDays = 90

// IAMCollector queries AWS IAM to collect evidence about user MFA
// enrollment and access key age. It calls ListUsers to enumerate all IAM
// users, then ListMFADevices for each user to check MFA status, and
// ListAccessKeys to check key age. Findings are generated for users
// without MFA and for access keys older than 90 days.
type IAMCollector struct{}

// Compile-time interface check.
var _ module.Collector = (*IAMCollector)(nil)

func (c *IAMCollector) ID() string           { return "aws.iam" }
func (c *IAMCollector) Name() string         { return "AWS IAM Collector" }
func (c *IAMCollector) Version() string      { return "0.1.0" }
func (c *IAMCollector) SourceSystem() string { return "aws" }
func (c *IAMCollector) EvidenceTypes() []int { return []int{1002} }

func (c *IAMCollector) CredentialRequirements() []module.CredentialReq {
	return []module.CredentialReq{
		{
			Name:        "AWS_ACCESS_KEY_ID",
			Type:        "api_key",
			Description: "AWS access key ID with IAM read permissions",
			Required:    true,
		},
		{
			Name:        "AWS_SECRET_ACCESS_KEY",
			Type:        "secret",
			Description: "AWS secret access key",
			Required:    true,
		},
		{
			Name:        "AWS_SESSION_TOKEN",
			Type:        "token",
			Description: "AWS session token for temporary credentials",
			Required:    false,
		},
		{
			Name:        "AWS_REGION",
			Type:        "config",
			Description: "AWS region (default: us-east-1)",
			Required:    false,
		},
	}
}

// ----- AWS IAM XML Response Structures -----

// listUsersResponse represents the XML response from IAM ListUsers.
type listUsersResponse struct {
	XMLName xml.Name       `xml:"ListUsersResponse"`
	Result  listUsersResult `xml:"ListUsersResult"`
}

type listUsersResult struct {
	Users       []iamUser `xml:"Users>member"`
	IsTruncated bool      `xml:"IsTruncated"`
	Marker      string    `xml:"Marker"`
}

type iamUser struct {
	UserName   string `xml:"UserName"`
	UserID     string `xml:"UserId"`
	Arn        string `xml:"Arn"`
	CreateDate string `xml:"CreateDate"`
}

// listMFADevicesResponse represents the XML response from IAM ListMFADevices.
type listMFADevicesResponse struct {
	XMLName xml.Name             `xml:"ListMFADevicesResponse"`
	Result  listMFADevicesResult `xml:"ListMFADevicesResult"`
}

type listMFADevicesResult struct {
	MFADevices []mfaDevice `xml:"MFADevices>member"`
}

type mfaDevice struct {
	SerialNumber string `xml:"SerialNumber"`
	EnableDate   string `xml:"EnableDate"`
}

// listAccessKeysResponse represents the XML response from IAM ListAccessKeys.
type listAccessKeysResponse struct {
	XMLName xml.Name              `xml:"ListAccessKeysResponse"`
	Result  listAccessKeysResult  `xml:"ListAccessKeysResult"`
}

type listAccessKeysResult struct {
	AccessKeyMetadata []accessKeyMetadata `xml:"AccessKeyMetadata>member"`
}

type accessKeyMetadata struct {
	AccessKeyID string `xml:"AccessKeyId"`
	Status      string `xml:"Status"`
	CreateDate  string `xml:"CreateDate"`
	UserName    string `xml:"UserName"`
}

// ----- Collector Implementation -----

// userMFAStatus holds the MFA and access key state for a single IAM user.
type userMFAStatus struct {
	UserName      string   `json:"user_name"`
	UserID        string   `json:"user_id"`
	Arn           string   `json:"arn"`
	MFAEnabled    bool     `json:"mfa_enabled"`
	MFADevices    int      `json:"mfa_devices"`
	AccessKeys    []accessKeyInfo `json:"access_keys"`
}

// accessKeyInfo captures relevant details about a single IAM access key.
type accessKeyInfo struct {
	AccessKeyID string `json:"access_key_id"`
	Status      string `json:"status"`
	AgeDays     int    `json:"age_days"`
	CreateDate  string `json:"create_date"`
}

// Collect queries AWS IAM to enumerate all users, check MFA enrollment,
// and inspect access key age. It returns a single evidence record with
// findings for any users lacking MFA or holding old access keys.
func (c *IAMCollector) Collect(ctx context.Context, config map[string]string) ([]evidence.Evidence, error) {
	client, err := newAWSClient(config)
	if err != nil {
		return nil, fmt.Errorf("creating AWS client: %w", err)
	}

	// IAM is a global service; always use us-east-1 for signing.
	client.region = "us-east-1"

	// Step 1: List all IAM users (handle pagination).
	users, err := listAllUsers(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("listing IAM users: %w", err)
	}

	// Step 2: For each user, check MFA devices and access keys.
	var statuses []userMFAStatus
	for _, user := range users {
		status, statusErr := getUserStatus(ctx, client, user)
		if statusErr != nil {
			return nil, fmt.Errorf("checking user %s: %w", user.UserName, statusErr)
		}
		statuses = append(statuses, status)
	}

	// Step 3: Build findings and determine overall status.
	now := time.Now().UTC()
	var findings []evidence.Finding
	var observables []evidence.Observable

	usersWithoutMFA := 0
	oldAccessKeys := 0

	for _, status := range statuses {
		observables = append(observables, evidence.Observable{
			Type:  "user",
			Value: status.UserName,
		})
		observables = append(observables, evidence.Observable{
			Type:  "resource",
			Value: status.Arn,
		})

		if !status.MFAEnabled {
			usersWithoutMFA++
			findings = append(findings, evidence.Finding{
				Title:       "User Without MFA",
				Description: fmt.Sprintf("IAM user %q does not have any MFA device configured", status.UserName),
				SeverityID:  3, // high
			})
		}

		for _, key := range status.AccessKeys {
			if key.Status == "Active" && key.AgeDays > accessKeyMaxAgeDays {
				oldAccessKeys++
				findings = append(findings, evidence.Finding{
					Title:       "Stale Access Key",
					Description: fmt.Sprintf("IAM user %q has active access key %s that is %d days old (max %d)", status.UserName, key.AccessKeyID, key.AgeDays, accessKeyMaxAgeDays),
					SeverityID:  2, // medium
				})
			}
		}
	}

	// If no findings, add an informational one.
	if len(findings) == 0 {
		findings = append(findings, evidence.Finding{
			Title:       "IAM Users Compliant",
			Description: fmt.Sprintf("All %d IAM users have MFA enabled and no stale access keys", len(statuses)),
			SeverityID:  0, // informational
		})
	}

	// Determine status.
	statusID := evidence.StatusEffective
	statusText := fmt.Sprintf("All %d IAM users have MFA enabled with no stale access keys", len(statuses))
	if usersWithoutMFA > 0 || oldAccessKeys > 0 {
		statusID = evidence.StatusIneffective
		statusText = fmt.Sprintf("%d users without MFA, %d stale access keys out of %d total users", usersWithoutMFA, oldAccessKeys, len(statuses))
	}

	// Build raw data.
	rawData := map[string]interface{}{
		"total_users":        len(statuses),
		"users_without_mfa":  usersWithoutMFA,
		"stale_access_keys":  oldAccessKeys,
		"max_key_age_days":   accessKeyMaxAgeDays,
		"user_details":       statuses,
	}
	rawJSON, _ := json.Marshal(rawData)

	ev := evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "iam.mfa_enforcement",
		ClassUID:        1002,
		CategoryUID:     1,
		ActivityID:      1, // Config Check
		Time:            now,
		ConfidenceLevel: evidence.PassiveObservation,
		Metadata: evidence.Metadata{
			Module: evidence.ModuleInfo{
				Name:    c.ID(),
				Version: c.Version(),
				Type:    "collector",
			},
			Source: evidence.SourceInfo{
				System:     "aws",
				APIVersion: iamAPIVersion,
				Endpoint:   iamEndpoint,
			},
			ProcessedTime: now,
		},
		Observables: observables,
		StatusID:    statusID,
		Status:      statusText,
		RawData:     rawJSON,
		Findings:    findings,
	}

	return []evidence.Evidence{ev}, nil
}

// listAllUsers retrieves all IAM users, handling pagination via markers.
func listAllUsers(ctx context.Context, client *awsClient) ([]iamUser, error) {
	var allUsers []iamUser
	marker := ""

	for {
		params := url.Values{}
		params.Set("Action", "ListUsers")
		params.Set("Version", iamAPIVersion)
		if marker != "" {
			params.Set("Marker", marker)
		}

		body, err := client.doRequest(ctx, "GET", iamEndpoint, params, iamService)
		if err != nil {
			return nil, err
		}

		var resp listUsersResponse
		if err := xml.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("parsing ListUsers response: %w", err)
		}

		allUsers = append(allUsers, resp.Result.Users...)

		if !resp.Result.IsTruncated {
			break
		}
		marker = resp.Result.Marker
	}

	return allUsers, nil
}

// getUserStatus retrieves MFA devices and access keys for a single IAM user.
func getUserStatus(ctx context.Context, client *awsClient, user iamUser) (userMFAStatus, error) {
	status := userMFAStatus{
		UserName: user.UserName,
		UserID:   user.UserID,
		Arn:      user.Arn,
	}

	// Check MFA devices.
	mfaParams := url.Values{}
	mfaParams.Set("Action", "ListMFADevices")
	mfaParams.Set("Version", iamAPIVersion)
	mfaParams.Set("UserName", user.UserName)

	mfaBody, err := client.doRequest(ctx, "GET", iamEndpoint, mfaParams, iamService)
	if err != nil {
		return status, fmt.Errorf("listing MFA devices: %w", err)
	}

	var mfaResp listMFADevicesResponse
	if err := xml.Unmarshal(mfaBody, &mfaResp); err != nil {
		return status, fmt.Errorf("parsing ListMFADevices response: %w", err)
	}

	status.MFADevices = len(mfaResp.Result.MFADevices)
	status.MFAEnabled = status.MFADevices > 0

	// Check access keys.
	keyParams := url.Values{}
	keyParams.Set("Action", "ListAccessKeys")
	keyParams.Set("Version", iamAPIVersion)
	keyParams.Set("UserName", user.UserName)

	keyBody, err := client.doRequest(ctx, "GET", iamEndpoint, keyParams, iamService)
	if err != nil {
		return status, fmt.Errorf("listing access keys: %w", err)
	}

	var keyResp listAccessKeysResponse
	if err := xml.Unmarshal(keyBody, &keyResp); err != nil {
		return status, fmt.Errorf("parsing ListAccessKeys response: %w", err)
	}

	now := time.Now().UTC()
	for _, key := range keyResp.Result.AccessKeyMetadata {
		ageDays := 0
		if createTime, parseErr := time.Parse(time.RFC3339, key.CreateDate); parseErr == nil {
			ageDays = int(now.Sub(createTime).Hours() / 24)
		}
		status.AccessKeys = append(status.AccessKeys, accessKeyInfo{
			AccessKeyID: key.AccessKeyID,
			Status:      key.Status,
			AgeDays:     ageDays,
			CreateDate:  key.CreateDate,
		})
	}

	return status, nil
}
