package eval

import (
	"encoding/json"

	"github.com/grcengineering/ocean/internal/evidence"
)

// EvidenceToMap converts a single Evidence record into a map[string]interface{}
// suitable for consumption by the CEL evaluation engine. This flattens the
// evidence struct into a dictionary that CEL can query with dot notation.
func EvidenceToMap(ev evidence.Evidence) map[string]interface{} {
	m := map[string]interface{}{
		"id":               ev.ID.String(),
		"control_id":       ev.ControlID,
		"class_uid":        int64(ev.ClassUID),
		"category_uid":     int64(ev.CategoryUID),
		"activity_id":      int64(ev.ActivityID),
		"time":             ev.Time.UTC().String(),
		"confidence_level": string(ev.ConfidenceLevel),
		"status_id":        int64(ev.StatusID),
		"status":           ev.Status,
	}

	// Add raw_data as a generic map if it can be parsed.
	if len(ev.RawData) > 0 {
		var rawMap interface{}
		if err := json.Unmarshal(ev.RawData, &rawMap); err == nil {
			m["raw_data"] = rawMap
		} else {
			m["raw_data"] = string(ev.RawData)
		}
	}

	// Add findings count.
	m["findings_count"] = int64(len(ev.Findings))

	// Add metadata fields.
	m["module_name"] = ev.Metadata.Module.Name
	m["module_type"] = ev.Metadata.Module.Type
	m["source_system"] = ev.Metadata.Source.System

	// Add test transcript presence.
	m["has_transcript"] = ev.TestTranscript != nil

	return m
}

// EvidencesToActivation converts a slice of Evidence records into the
// activation map consumed by the CEL evaluation engine. The activation map
// provides:
//
//   - evidence: list of evidence maps (each from EvidenceToMap)
//   - status_counts: map with keys effective, ineffective, unknown, total
//   - has_active: bool (true if any evidence has ActiveVerification confidence)
//   - has_passive: bool (true if any evidence has PassiveObservation confidence)
func EvidencesToActivation(evs []evidence.Evidence) map[string]interface{} {
	// Build evidence list.
	evidenceList := make([]interface{}, 0, len(evs))
	for _, ev := range evs {
		evidenceList = append(evidenceList, EvidenceToMap(ev))
	}

	// Count statuses.
	var effective, ineffective, unknown int64
	hasActive := false
	hasPassive := false

	for _, ev := range evs {
		switch ev.StatusID {
		case evidence.StatusEffective:
			effective++
		case evidence.StatusIneffective:
			ineffective++
		default:
			unknown++
		}

		switch ev.ConfidenceLevel {
		case evidence.ActiveVerification:
			hasActive = true
		case evidence.PassiveObservation:
			hasPassive = true
		}
	}

	total := int64(len(evs))

	statusCounts := map[string]interface{}{
		"effective":   effective,
		"ineffective": ineffective,
		"unknown":     unknown,
		"total":       total,
	}

	return map[string]interface{}{
		"evidence":      evidenceList,
		"status_counts": statusCounts,
		"has_active":    hasActive,
		"has_passive":   hasPassive,
	}
}
