package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/grcengineering/ocean/internal/attestation"
	"github.com/grcengineering/ocean/internal/config"
	"github.com/grcengineering/ocean/internal/control"
	"github.com/grcengineering/ocean/internal/eval"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/storage"
	sqlitestore "github.com/grcengineering/ocean/internal/storage/sqlite"
)

var (
	celFlag         string
	evalControlsDir string
)

var evaluateCmd = &cobra.Command{
	Use:   "evaluate <control>",
	Short: "Evaluate a control using its evidence and CEL evaluation logic",
	Long: `Evaluate a control by loading its definition, querying stored evidence,
and evaluating the control's CEL expression (or preset) against the evidence.

The result is a ControlStatus with an effective/ineffective/unknown verdict,
stored in SQLite with an optional signed evaluation attestation.

Examples:
  ocean evaluate AC-MFA-001
  ocean evaluate AC-MFA-001 --cel "status_counts.effective > 0"
  ocean evaluate AC-MFA-001 --controls-dir ./my-controls`,
	Args: cobra.ExactArgs(1),
	RunE: runEvaluate,
}

func init() {
	evaluateCmd.Flags().StringVar(&celFlag, "cel", "", "ad-hoc CEL expression (overrides control definition)")
	evaluateCmd.Flags().StringVar(&evalControlsDir, "controls-dir", "", "directory containing control YAML definitions")
}

func runEvaluate(cmd *cobra.Command, args []string) error {
	controlID := args[0]

	// Load configuration.
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Determine controls directory.
	ctrlDir := evalControlsDir
	if ctrlDir == "" {
		ctrlDir = expandPath(cfg.ControlsDir)
	}

	// Load control definition.
	ctrl, err := findControl(ctrlDir, controlID)
	if err != nil {
		return fmt.Errorf("loading control %s: %w", controlID, err)
	}

	// Open SQLite store.
	storagePath := expandPath(cfg.StoragePath)
	store, err := sqlitestore.Open(storagePath)
	if err != nil {
		return fmt.Errorf("opening storage: %w", err)
	}
	defer store.Close()

	// Query stored evidence for this control.
	ctx := context.Background()
	evidences, err := store.QueryEvidence(ctx, storage.EvidenceQuery{
		ControlID: controlID,
	})
	if err != nil {
		return fmt.Errorf("querying evidence: %w", err)
	}

	log.Info().
		Str("control", controlID).
		Int("evidence_count", len(evidences)).
		Msg("evaluating control")

	// Perform CEL evaluation.
	cs, err := control.CELEvaluateControl(ctrl, evidences, celFlag)
	if err != nil {
		return fmt.Errorf("CEL evaluation failed: %w", err)
	}

	// Attempt to create signed evaluation attestation.
	if err := signAndStoreEvaluation(ctx, cfg, store, ctrl, cs, evidences); err != nil {
		log.Warn().Err(err).Msg("evaluation attestation not created")
	}

	// Store the control status in SQLite.
	if err := store.StoreControlStatus(ctx, *cs); err != nil {
		return fmt.Errorf("storing control status: %w", err)
	}

	// Output the result.
	if err := PrintOutput(os.Stdout, cs, outputFormat); err != nil {
		return fmt.Errorf("output failed: %w", err)
	}

	return nil
}

// findControl locates a control definition by ID within the controls directory.
func findControl(dir, controlID string) (*control.Control, error) {
	controls, err := control.LoadAllControls(dir)
	if err != nil {
		return nil, fmt.Errorf("loading controls from %s: %w", dir, err)
	}

	for _, ctrl := range controls {
		if ctrl.ID == controlID {
			return ctrl, nil
		}
	}

	return nil, fmt.Errorf("control %q not found in %s", controlID, dir)
}

// signAndStoreEvaluation creates a signed evaluation attestation if a signing
// key is available, and links it to the ControlStatus.
func signAndStoreEvaluation(
	ctx context.Context,
	cfg *config.Config,
	store storage.Store,
	ctrl *control.Control,
	cs *control.ControlStatus,
	evidences []evidence.Evidence,
) error {
	// Load signer.
	keyPath := expandPath(cfg.KeyPath)
	privKeyFile := filepath.Join(keyPath, "ocean-ed25519.key")

	signer, err := attestation.LoadSigner(privKeyFile)
	if err != nil {
		return fmt.Errorf("no signing key available: %w", err)
	}

	// Compute evidence digests for the attestation.
	var evidenceDigests []string
	for _, ev := range evidences {
		digest := attestation.DigestOf(ev.RawData)
		evidenceDigests = append(evidenceDigests, digest)
	}

	// Resolve the expression that was used.
	expr, err := eval.ResolveExpression(ctrl.EvaluationLogic.CELExpression, ctrl.EvaluationLogic.Preset)
	if err != nil {
		// If we can't resolve, use what we have.
		expr = ctrl.EvaluationLogic.CELExpression
	}
	exprDigest := eval.ContentAddress(expr)

	// Create evaluation attestation.
	stmt, err := attestation.NewEvaluationAttestation(
		ctrl.ID,
		evidenceDigests,
		exprDigest,
		expr,
		cs.Status,
		cs.Confidence,
	)
	if err != nil {
		return fmt.Errorf("creating evaluation attestation: %w", err)
	}

	// Sign it.
	envelope, ref, err := attestation.SignEvaluation(stmt, signer)
	if err != nil {
		return fmt.Errorf("signing evaluation attestation: %w", err)
	}

	// Store the envelope.
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshaling evaluation envelope: %w", err)
	}

	if err := store.StoreAttestation(ctx, ref, envelopeJSON); err != nil {
		return fmt.Errorf("storing evaluation attestation: %w", err)
	}

	// Link the attestation to the control status.
	cs.EvaluationAttestationRef = ref

	return nil
}
