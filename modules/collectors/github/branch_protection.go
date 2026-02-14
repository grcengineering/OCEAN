package github

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
)

// BranchProtectionCollector queries GitHub's branch protection API to
// gather evidence about repository branch protection rules. It checks
// for required reviews, status checks, force-push restrictions, and
// other protections that indicate secure development practices.
type BranchProtectionCollector struct{}

// Compile-time interface check.
var _ module.Collector = (*BranchProtectionCollector)(nil)

func (c *BranchProtectionCollector) ID() string           { return "github.branch_protection" }
func (c *BranchProtectionCollector) Name() string          { return "GitHub Branch Protection Collector" }
func (c *BranchProtectionCollector) Version() string       { return "0.1.0" }
func (c *BranchProtectionCollector) SourceSystem() string  { return "github" }
func (c *BranchProtectionCollector) EvidenceTypes() []int  { return []int{1003} }

func (c *BranchProtectionCollector) CredentialRequirements() []module.CredentialReq {
	return []module.CredentialReq{
		{
			Name:        "GITHUB_TOKEN",
			Type:        "api_token",
			Description: "GitHub personal access token with repo scope for reading branch protection rules",
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
			Description: "GitHub repository name",
			Required:    true,
		},
		{
			Name:        "GITHUB_BRANCH",
			Type:        "config",
			Description: "Branch to check protection rules for (default: main)",
			Required:    false,
		},
	}
}

// branchProtectionResponse represents the relevant fields from GitHub's
// branch protection API response.
type branchProtectionResponse struct {
	URL                       string                     `json:"url"`
	RequiredStatusChecks      *requiredStatusChecks      `json:"required_status_checks"`
	EnforceAdmins             *enforceAdmins             `json:"enforce_admins"`
	RequiredPullRequestReviews *requiredPullRequestReviews `json:"required_pull_request_reviews"`
	Restrictions              *restrictions              `json:"restrictions"`
	RequiredLinearHistory     *requiredLinearHistory     `json:"required_linear_history"`
	AllowForcePushes          *allowForcePushes          `json:"allow_force_pushes"`
	AllowDeletions            *allowDeletions            `json:"allow_deletions"`
	RequiredSignatures        *requiredSignatures        `json:"required_signatures"`
}

type requiredStatusChecks struct {
	Strict   bool     `json:"strict"`
	Contexts []string `json:"contexts"`
}

type enforceAdmins struct {
	Enabled bool `json:"enabled"`
}

type requiredPullRequestReviews struct {
	DismissStaleReviews          bool `json:"dismiss_stale_reviews"`
	RequireCodeOwnerReviews      bool `json:"require_code_owner_reviews"`
	RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
}

type restrictions struct {
	Users []interface{} `json:"users"`
	Teams []interface{} `json:"teams"`
	Apps  []interface{} `json:"apps"`
}

type requiredLinearHistory struct {
	Enabled bool `json:"enabled"`
}

type allowForcePushes struct {
	Enabled bool `json:"enabled"`
}

type allowDeletions struct {
	Enabled bool `json:"enabled"`
}

type requiredSignatures struct {
	Enabled bool `json:"enabled"`
}

// Collect queries the GitHub branch protection API and returns evidence
// describing the protection state of the configured branch. Findings
// are generated for each missing or weak protection.
func (c *BranchProtectionCollector) Collect(ctx context.Context, config map[string]string) ([]evidence.Evidence, error) {
	_ = ctx // Reserved for future cancellation support.

	ghClient, err := newClient(config)
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

	branch := config["GITHUB_BRANCH"]
	if branch == "" {
		branch = "main"
	}

	endpoint := fmt.Sprintf("/repos/%s/%s/branches/%s/protection", owner, repo, branch)
	body, statusCode, err := ghClient.get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("querying branch protection: %w", err)
	}

	now := time.Now().UTC()

	// A 404 means branch protection is not enabled at all.
	if statusCode == 404 {
		return c.buildNoProtectionEvidence(now, owner, repo, branch, body), nil
	}

	if statusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned status %d for %s", statusCode, endpoint)
	}

	var protection branchProtectionResponse
	if err := json.Unmarshal(body, &protection); err != nil {
		return nil, fmt.Errorf("parsing branch protection response: %w", err)
	}

	return c.buildProtectionEvidence(now, owner, repo, branch, &protection, body), nil
}

// buildNoProtectionEvidence creates evidence when branch protection is
// completely disabled (404 response).
func (c *BranchProtectionCollector) buildNoProtectionEvidence(
	now time.Time, owner, repo, branch string, rawBody json.RawMessage,
) []evidence.Evidence {
	ev := evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "scm.branch_protection",
		ClassUID:        1003,
		CategoryUID:     2,
		ActivityID:      1,
		Time:            now,
		ConfidenceLevel: evidence.PassiveObservation,
		Metadata: evidence.Metadata{
			Module: evidence.ModuleInfo{
				Name:    "github.branch_protection",
				Version: "0.1.0",
				Type:    "collector",
			},
			Source: evidence.SourceInfo{
				System:     "github",
				APIVersion: "v3",
				Endpoint:   fmt.Sprintf("/repos/%s/%s/branches/%s/protection", owner, repo, branch),
			},
			ProcessedTime: now,
		},
		Observables: []evidence.Observable{
			{Type: "resource", Value: fmt.Sprintf("%s/%s:%s:branch_protection", owner, repo, branch)},
			{Type: "domain", Value: "github.com"},
		},
		StatusID: evidence.StatusIneffective,
		Status:   fmt.Sprintf("Branch protection is not enabled on %s/%s branch %s", owner, repo, branch),
		RawData:  rawBody,
		Findings: []evidence.Finding{
			{
				Title:       "Branch Protection Disabled",
				Description: fmt.Sprintf("No branch protection rules are configured for %s/%s branch %s. This allows unrestricted pushes, force pushes, and deletions.", owner, repo, branch),
				SeverityID:  4, // high
			},
		},
	}

	return []evidence.Evidence{ev}
}

// buildProtectionEvidence creates evidence from a successful branch
// protection API response, generating findings for each weak or missing
// protection rule.
func (c *BranchProtectionCollector) buildProtectionEvidence(
	now time.Time, owner, repo, branch string,
	protection *branchProtectionResponse, rawBody json.RawMessage,
) []evidence.Evidence {
	var findings []evidence.Finding
	statusID := evidence.StatusEffective
	statusMsg := fmt.Sprintf("Branch protection is properly configured on %s/%s branch %s", owner, repo, branch)

	// Check required pull request reviews.
	if protection.RequiredPullRequestReviews == nil {
		findings = append(findings, evidence.Finding{
			Title:       "Pull Request Reviews Not Required",
			Description: "Branch protection does not require pull request reviews before merging. Code changes can be merged without peer review.",
			SeverityID:  3, // medium
		})
		statusID = evidence.StatusIneffective
	} else {
		if protection.RequiredPullRequestReviews.RequiredApprovingReviewCount < 1 {
			findings = append(findings, evidence.Finding{
				Title:       "No Minimum Review Count",
				Description: "Pull request reviews are configured but no minimum approving review count is set.",
				SeverityID:  2, // low
			})
		}
		if !protection.RequiredPullRequestReviews.DismissStaleReviews {
			findings = append(findings, evidence.Finding{
				Title:       "Stale Reviews Not Dismissed",
				Description: "Stale pull request reviews are not automatically dismissed when new commits are pushed. Approved reviews may not reflect the latest code changes.",
				SeverityID:  2, // low
			})
		}
	}

	// Check required status checks.
	if protection.RequiredStatusChecks == nil {
		findings = append(findings, evidence.Finding{
			Title:       "Status Checks Not Required",
			Description: "Branch protection does not require status checks before merging. Code can be merged without passing CI/CD pipelines.",
			SeverityID:  3, // medium
		})
		statusID = evidence.StatusIneffective
	} else if len(protection.RequiredStatusChecks.Contexts) == 0 {
		findings = append(findings, evidence.Finding{
			Title:       "No Status Check Contexts Defined",
			Description: "Status checks are required but no specific check contexts are configured. Any status check will satisfy the requirement.",
			SeverityID:  2, // low
		})
	}

	// Check admin enforcement.
	if protection.EnforceAdmins == nil || !protection.EnforceAdmins.Enabled {
		findings = append(findings, evidence.Finding{
			Title:       "Admin Enforcement Disabled",
			Description: "Branch protection rules are not enforced for repository administrators. Admins can bypass all protection rules.",
			SeverityID:  2, // low
		})
	}

	// Check force push.
	if protection.AllowForcePushes != nil && protection.AllowForcePushes.Enabled {
		findings = append(findings, evidence.Finding{
			Title:       "Force Pushes Allowed",
			Description: "Force pushes are allowed on this branch. This enables rewriting commit history, which can destroy audit trails and overwrite peer-reviewed code.",
			SeverityID:  3, // medium
		})
		statusID = evidence.StatusIneffective
	}

	// Check branch deletion.
	if protection.AllowDeletions != nil && protection.AllowDeletions.Enabled {
		findings = append(findings, evidence.Finding{
			Title:       "Branch Deletion Allowed",
			Description: "Branch deletion is allowed. The protected branch can be deleted, potentially destroying code and history.",
			SeverityID:  3, // medium
		})
		statusID = evidence.StatusIneffective
	}

	// If there are high-severity findings, update the status message.
	if statusID == evidence.StatusIneffective {
		statusMsg = fmt.Sprintf("Branch protection on %s/%s branch %s has gaps", owner, repo, branch)
	}

	// If no findings at all, add a positive finding.
	if len(findings) == 0 {
		findings = append(findings, evidence.Finding{
			Title:       "Branch Protection Properly Configured",
			Description: fmt.Sprintf("Branch protection on %s/%s branch %s includes required reviews, status checks, and force-push restrictions.", owner, repo, branch),
			SeverityID:  0, // informational
		})
	}

	ev := evidence.Evidence{
		ID:              uuid.New(),
		ControlID:       "scm.branch_protection",
		ClassUID:        1003,
		CategoryUID:     2,
		ActivityID:      1,
		Time:            now,
		ConfidenceLevel: evidence.PassiveObservation,
		Metadata: evidence.Metadata{
			Module: evidence.ModuleInfo{
				Name:    "github.branch_protection",
				Version: "0.1.0",
				Type:    "collector",
			},
			Source: evidence.SourceInfo{
				System:     "github",
				APIVersion: "v3",
				Endpoint:   fmt.Sprintf("/repos/%s/%s/branches/%s/protection", owner, repo, branch),
			},
			ProcessedTime: now,
		},
		Observables: []evidence.Observable{
			{Type: "resource", Value: fmt.Sprintf("%s/%s:%s:branch_protection", owner, repo, branch)},
			{Type: "domain", Value: "github.com"},
		},
		StatusID: statusID,
		Status:   statusMsg,
		RawData:  rawBody,
		Findings: findings,
	}

	return []evidence.Evidence{ev}
}
