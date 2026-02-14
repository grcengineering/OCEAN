package schema

import "time"

// Control is the public representation of an OCEAN control definition.
// This type is stable and safe for use in external integrations.
type Control struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name"`
	Description          string             `json:"description"`
	ThreatMitigated      string             `json:"threat_mitigated"`
	FrameworkMappings    []FrameworkMapping  `json:"framework_mappings,omitempty"`
	EvidenceRequirements []string           `json:"evidence_requirements"`
	Collectors           []string           `json:"collectors"`
	Testers              []string           `json:"testers,omitempty"`
	EvaluationLogic      EvaluationLogic    `json:"evaluation_logic"`
}

// FrameworkMapping links a control to an external framework reference.
type FrameworkMapping struct {
	FrameworkID string `json:"framework_id"`
	ControlRef  string `json:"control_ref"`
}

// EvaluationLogic defines how evidence is evaluated for a control.
type EvaluationLogic struct {
	CELExpression string `json:"cel_expression,omitempty"`
	Preset        string `json:"preset,omitempty"`
}

// ControlStatus represents the evaluated state of a control at a point in time.
type ControlStatus struct {
	ID                string    `json:"id"`
	ControlID         string    `json:"control_id"`
	Timestamp         time.Time `json:"timestamp"`
	Status            string    `json:"status"`
	Confidence        string    `json:"confidence"`
	EvidenceIDs       []string  `json:"evidence_ids"`
	EvaluationDetails string    `json:"evaluation_details"`
}

// UptimeResult holds the result of an uptime calculation.
type UptimeResult struct {
	ControlID          string    `json:"control_id"`
	FromTime           time.Time `json:"from"`
	ToTime             time.Time `json:"to"`
	TotalBuckets       int       `json:"total_buckets"`
	EffectiveBuckets   int       `json:"effective_buckets"`
	IneffectiveBuckets int       `json:"ineffective_buckets"`
	GapBuckets         int       `json:"gap_buckets"`
	UptimePercent      float64   `json:"uptime_percent"`
}
