// Package ocean provides the public Go library API for embedding OCEAN's
// evidence collection, testing, evaluation, and query capabilities into
// external GRC platforms and automation pipelines.
//
// This is a thin wrapper around internal packages, providing a stable
// public interface that will not change with internal refactoring.
package ocean

import (
	"context"
	"fmt"
	"time"

	"github.com/grcengineering/ocean/internal/control"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/module"
	"github.com/grcengineering/ocean/internal/storage"
	sqlitestore "github.com/grcengineering/ocean/internal/storage/sqlite"
	"github.com/grcengineering/ocean/pkg/schema"
)

// Config configures an OCEAN client instance.
type Config struct {
	// StoragePath is the path to the SQLite database file.
	// If empty, defaults to ~/.ocean/ocean.db.
	StoragePath string

	// ControlsDir is the path to the directory containing control YAML definitions.
	// If empty, controls must be registered manually.
	ControlsDir string
}

// Client is the primary entry point for OCEAN's public Go library API.
// It provides methods for collecting evidence, running tests, evaluating
// controls, and querying history.
type Client struct {
	store    storage.Store
	registry *module.Registry
	controls []*control.Control
}

// NewClient creates a new OCEAN client with the given configuration.
// The caller is responsible for calling Close() when done.
func NewClient(cfg Config) (*Client, error) {
	if cfg.StoragePath == "" {
		cfg.StoragePath = "ocean.db"
	}

	store, err := sqlitestore.Open(cfg.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("opening storage: %w", err)
	}

	reg := module.NewRegistry()

	var controls []*control.Control
	if cfg.ControlsDir != "" {
		controls, err = control.LoadAllControls(cfg.ControlsDir)
		if err != nil {
			store.Close()
			return nil, fmt.Errorf("loading controls: %w", err)
		}
	}

	return &Client{
		store:    store,
		registry: reg,
		controls: controls,
	}, nil
}

// Registry returns the module registry for registering custom collectors and testers.
func (c *Client) Registry() *module.Registry {
	return c.registry
}

// Collect runs a collector module by ID and returns the collected evidence.
func (c *Client) Collect(ctx context.Context, moduleID string, config map[string]string) ([]schema.Evidence, error) {
	collector, err := c.registry.GetCollector(moduleID)
	if err != nil {
		return nil, fmt.Errorf("getting collector: %w", err)
	}

	evs, err := collector.Collect(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("collecting evidence: %w", err)
	}

	// Store and convert to public types.
	result := make([]schema.Evidence, 0, len(evs))
	for _, ev := range evs {
		if storeErr := c.store.StoreEvidence(ctx, ev); storeErr != nil {
			return nil, fmt.Errorf("storing evidence: %w", storeErr)
		}
		result = append(result, toPublicEvidence(ev))
	}

	return result, nil
}

// Test runs a tester module by ID and returns the test evidence.
func (c *Client) Test(ctx context.Context, moduleID string, config map[string]string) ([]schema.Evidence, error) {
	tester, err := c.registry.GetTester(moduleID)
	if err != nil {
		return nil, fmt.Errorf("getting tester: %w", err)
	}

	evs, err := tester.Test(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("running test: %w", err)
	}

	result := make([]schema.Evidence, 0, len(evs))
	for _, ev := range evs {
		if storeErr := c.store.StoreEvidence(ctx, ev); storeErr != nil {
			return nil, fmt.Errorf("storing evidence: %w", storeErr)
		}
		result = append(result, toPublicEvidence(ev))
	}

	return result, nil
}

// Evaluate evaluates a control's effectiveness based on stored evidence.
// Returns the control status after evaluation.
func (c *Client) Evaluate(ctx context.Context, controlID string) (*schema.ControlStatus, error) {
	ctrl := c.findControl(controlID)
	if ctrl == nil {
		return nil, fmt.Errorf("control %q not found", controlID)
	}

	// Query recent evidence for this control.
	evs, err := c.store.QueryEvidence(ctx, storage.EvidenceQuery{
		ControlID: controlID,
		Limit:     100,
	})
	if err != nil {
		return nil, fmt.Errorf("querying evidence: %w", err)
	}

	// Evaluate using CEL if expression is defined, otherwise use basic evaluation.
	var cs *control.ControlStatus
	if ctrl.EvaluationLogic.CELExpression != "" || ctrl.EvaluationLogic.Preset != "" {
		cs, err = control.CELEvaluateControl(ctrl, evs, "")
	} else {
		cs, err = control.EvaluateControl(ctrl, evs)
	}
	if err != nil {
		return nil, fmt.Errorf("evaluating control: %w", err)
	}

	// Store the control status.
	if storeErr := c.store.StoreControlStatus(ctx, *cs); storeErr != nil {
		return nil, fmt.Errorf("storing control status: %w", storeErr)
	}

	return toPublicControlStatus(cs), nil
}

// History returns the historical effectiveness of a control over a time range.
func (c *Client) History(ctx context.Context, controlID string, from, to time.Time) ([]schema.ControlStatus, error) {
	statuses, err := c.store.QueryHistory(ctx, controlID, from, to)
	if err != nil {
		return nil, fmt.Errorf("querying history: %w", err)
	}

	result := make([]schema.ControlStatus, 0, len(statuses))
	for _, cs := range statuses {
		result = append(result, *toPublicControlStatus(&cs))
	}

	return result, nil
}

// Close releases all resources held by the client.
func (c *Client) Close() error {
	return c.store.Close()
}

// findControl returns the control definition with the given ID, or nil if not found.
func (c *Client) findControl(id string) *control.Control {
	for _, ctrl := range c.controls {
		if ctrl.ID == id {
			return ctrl
		}
	}
	return nil
}

// --- conversion helpers ---

func toPublicEvidence(ev evidence.Evidence) schema.Evidence {
	return schema.Evidence{
		ID:              ev.ID.String(),
		ControlID:       ev.ControlID,
		ClassUID:        ev.ClassUID,
		CategoryUID:     ev.CategoryUID,
		ActivityID:      ev.ActivityID,
		Time:            ev.Time,
		ConfidenceLevel: schema.ConfidenceLevel(ev.ConfidenceLevel),
		StatusID:        schema.StatusID(ev.StatusID),
		Status:          ev.Status,
		RawData:         ev.RawData,
		Metadata: schema.Metadata{
			Module: schema.ModuleInfo{
				Name:    ev.Metadata.Module.Name,
				Version: ev.Metadata.Module.Version,
				Type:    ev.Metadata.Module.Type,
			},
			Source: schema.SourceInfo{
				System:     ev.Metadata.Source.System,
				APIVersion: ev.Metadata.Source.APIVersion,
				Endpoint:   ev.Metadata.Source.Endpoint,
			},
		},
		Attestation: schema.AttestationRef{
			Type:            ev.Attestation.Type,
			DSSEEnvelopeRef: ev.Attestation.DSSEEnvelopeRef,
			Digest:          ev.Attestation.Digest,
			Signer:          ev.Attestation.Signer,
		},
	}
}

func toPublicControlStatus(cs *control.ControlStatus) *schema.ControlStatus {
	ids := make([]string, 0, len(cs.EvidenceIDs))
	for _, id := range cs.EvidenceIDs {
		ids = append(ids, id.String())
	}

	return &schema.ControlStatus{
		ID:                cs.ID.String(),
		ControlID:         cs.ControlID,
		Timestamp:         cs.Timestamp,
		Status:            cs.Status,
		Confidence:        cs.Confidence,
		EvidenceIDs:       ids,
		EvaluationDetails: cs.EvaluationDetails,
	}
}
