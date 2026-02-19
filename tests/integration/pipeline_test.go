//go:build integration

package integration

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/grcengineering/ocean/internal/module"
	"github.com/grcengineering/ocean/internal/storage"
	sqlitestore "github.com/grcengineering/ocean/internal/storage/sqlite"
	"github.com/grcengineering/ocean/internal/testutil"
)

// TestCollectStoreEvaluate verifies the full pipeline: register a stub
// collector, collect evidence, store it in SQLite, query it back, and
// confirm the stored records match what was collected.
func TestCollectStoreEvaluate(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "pipeline.db")

	store, err := sqlitestore.Open(dbPath)
	if err != nil {
		t.Fatalf("opening SQLite store: %v", err)
	}
	defer store.Close()

	// Register a stub collector in a fresh registry.
	reg := module.NewRegistry()
	collector := testutil.NewStubCollector("integration.test_collector")
	reg.RegisterCollector(collector)

	// Verify registration.
	testutil.AssertModuleRegistered(t, reg, "integration.test_collector")

	// Collect evidence.
	ctx := context.Background()
	evs, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(evs) == 0 {
		t.Fatal("Collect returned no evidence")
	}

	// Store evidence in SQLite.
	for _, ev := range evs {
		if err := store.StoreEvidence(ctx, ev); err != nil {
			t.Fatalf("StoreEvidence: %v", err)
		}
	}

	// Query stored evidence back and verify it exists.
	query := storage.EvidenceQuery{
		ControlID: evs[0].ControlID,
		Limit:     10,
	}
	stored, err := store.QueryEvidence(ctx, query)
	if err != nil {
		t.Fatalf("QueryEvidence: %v", err)
	}
	if len(stored) == 0 {
		t.Fatal("QueryEvidence returned no results after storing evidence")
	}

	// Verify the stored evidence matches the original.
	if stored[0].ID != evs[0].ID {
		t.Errorf("stored evidence ID %s does not match original %s", stored[0].ID, evs[0].ID)
	}
	if stored[0].ControlID != evs[0].ControlID {
		t.Errorf("stored evidence ControlID %q does not match original %q", stored[0].ControlID, evs[0].ControlID)
	}

	// Validate evidence structure.
	for _, ev := range stored {
		testutil.AssertValidEvidence(t, ev)
	}
}

// TestMultiModulePipeline verifies that both a collector and a tester can
// be registered, executed, and their evidence stored in the same SQLite
// database. This confirms the pipeline handles mixed module types correctly.
func TestMultiModulePipeline(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "multi.db")

	store, err := sqlitestore.Open(dbPath)
	if err != nil {
		t.Fatalf("opening SQLite store: %v", err)
	}
	defer store.Close()

	// Register both a collector and a tester.
	reg := module.NewRegistry()
	collector := testutil.NewStubCollector("integration.multi_collector")
	tester := testutil.NewStubTester("integration.multi_tester")
	reg.RegisterCollector(collector)
	reg.RegisterTester(tester)

	ctx := context.Background()

	// Collect evidence from the collector.
	collectorEvs, err := collector.Collect(ctx, nil)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, ev := range collectorEvs {
		if err := store.StoreEvidence(ctx, ev); err != nil {
			t.Fatalf("StoreEvidence (collector): %v", err)
		}
	}

	// Run the tester and store its evidence.
	testerEvs, err := tester.Test(ctx, nil)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	for _, ev := range testerEvs {
		if err := store.StoreEvidence(ctx, ev); err != nil {
			t.Fatalf("StoreEvidence (tester): %v", err)
		}
	}

	// Query all evidence and verify both records are stored.
	allEvidence, err := store.QueryEvidence(ctx, storage.EvidenceQuery{
		ControlID: "test.control",
		Limit:     100,
	})
	if err != nil {
		t.Fatalf("QueryEvidence: %v", err)
	}

	expectedCount := len(collectorEvs) + len(testerEvs)
	if len(allEvidence) != expectedCount {
		t.Errorf("expected %d evidence records, got %d", expectedCount, len(allEvidence))
	}

	// Verify that we have both passive and active evidence.
	hasPassive := false
	hasActive := false
	for _, ev := range allEvidence {
		switch ev.ConfidenceLevel {
		case "passive_observation":
			hasPassive = true
		case "active_verification":
			hasActive = true
		}
	}
	if !hasPassive {
		t.Error("expected at least one passive_observation evidence record")
	}
	if !hasActive {
		t.Error("expected at least one active_verification evidence record")
	}
}
