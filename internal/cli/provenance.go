package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/grcengineering/ocean/internal/attestation"
	"github.com/grcengineering/ocean/internal/config"
	sqlitestore "github.com/grcengineering/ocean/internal/storage/sqlite"
)

var verifyProvenanceCmd = &cobra.Command{
	Use:   "verify-provenance",
	Short: "Verify cryptographic provenance of evidence records",
	Long: `Verify the cryptographic provenance chain of an evidence record.

This command loads the evidence and its attestation(s) from storage, then
verifies each step of the provenance chain:

  1. Evidence content digest matches attestation
  2. DSSE envelope signature is valid
  3. Signer identity matches signing key
  4. Test transcript digest matches (if applicable)

Use --export to export the attestation chain and public key for third-party
verification without needing an OCEAN instance.

Examples:
  ocean verify-provenance --evidence <uuid>
  ocean verify-provenance --export <uuid> --output-dir ./export`,
}

var verifyProvenanceRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run provenance chain verification for an evidence record",
	Args:  cobra.NoArgs,
	RunE:  runVerifyProvenance,
}

var verifyProvenanceExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export attestation chain and public key for third-party verification",
	Args:  cobra.NoArgs,
	RunE:  runExportProvenance,
}

func init() {
	// Flags for the parent command (shared).
	verifyProvenanceCmd.PersistentFlags().String("evidence", "", "Evidence UUID to verify (required)")
	verifyProvenanceCmd.PersistentFlags().String("key-dir", "", "directory for key storage (default: ~/.ocean/keys/)")

	// Flags for the run subcommand.
	// (inherits --evidence and --key-dir from parent)

	// Flags for the export subcommand.
	verifyProvenanceExportCmd.Flags().String("output-dir", ".", "directory to write exported files")

	verifyProvenanceCmd.AddCommand(verifyProvenanceRunCmd)
	verifyProvenanceCmd.AddCommand(verifyProvenanceExportCmd)

	// Also support running directly without subcommand (default to run).
	verifyProvenanceCmd.RunE = runVerifyProvenance
}

func runVerifyProvenance(cmd *cobra.Command, args []string) error {
	evidenceIDStr, err := cmd.Flags().GetString("evidence")
	if err != nil {
		return err
	}
	if evidenceIDStr == "" {
		return fmt.Errorf("--evidence flag is required")
	}

	evidenceID, err := uuid.Parse(evidenceIDStr)
	if err != nil {
		return fmt.Errorf("invalid evidence UUID: %w", err)
	}

	// Load configuration.
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Open SQLite store.
	storagePath := expandPath(cfg.StoragePath)
	store, err := sqlitestore.Open(storagePath)
	if err != nil {
		return fmt.Errorf("opening storage: %w", err)
	}
	defer store.Close()

	// Load signing key for verification.
	keyDir, _ := cmd.Flags().GetString("key-dir")
	if keyDir == "" {
		keyDir = expandPath(cfg.KeyPath)
	}

	pubKeyPath := filepath.Join(keyDir, "ocean-ed25519.pub")
	publicKey, err := attestation.LoadPublicKey(pubKeyPath)
	if err != nil {
		return fmt.Errorf("loading public key from %s: %w", pubKeyPath, err)
	}

	// Run the provenance chain verification.
	ctx := context.Background()
	result, err := attestation.VerifyProvenanceChain(ctx, store, evidenceID, publicKey)
	if err != nil {
		return fmt.Errorf("provenance verification failed: %w", err)
	}

	// Display step-by-step results.
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Provenance Verification for Evidence %s\n", evidenceID)
	fmt.Fprintf(w, "=========================================\n\n")

	for _, step := range result.StepResults {
		status := "PASS"
		if !step.Passed {
			status = "FAIL"
		}
		fmt.Fprintf(w, "  [%s] %s\n", status, step.StepName)
		fmt.Fprintf(w, "        %s\n", step.Details)
	}

	fmt.Fprintln(w)
	if result.Overall {
		fmt.Fprintf(w, "Overall: PASSED - provenance chain is intact\n")
	} else {
		fmt.Fprintf(w, "Overall: FAILED - provenance chain verification failed\n")
	}

	// Also output as JSON if format is json.
	if outputFormat == "json" {
		fmt.Fprintln(w)
		return PrintOutput(os.Stdout, result, outputFormat)
	}

	if !result.Overall {
		return fmt.Errorf("provenance verification failed")
	}
	return nil
}

func runExportProvenance(cmd *cobra.Command, args []string) error {
	evidenceIDStr, err := cmd.Flags().GetString("evidence")
	if err != nil {
		return err
	}
	if evidenceIDStr == "" {
		return fmt.Errorf("--evidence flag is required")
	}

	evidenceID, err := uuid.Parse(evidenceIDStr)
	if err != nil {
		return fmt.Errorf("invalid evidence UUID: %w", err)
	}

	outputDir, err := cmd.Flags().GetString("output-dir")
	if err != nil {
		return err
	}

	// Load configuration.
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Open SQLite store.
	storagePath := expandPath(cfg.StoragePath)
	store, err := sqlitestore.Open(storagePath)
	if err != nil {
		return fmt.Errorf("opening storage: %w", err)
	}
	defer store.Close()

	// Load the evidence.
	ctx := context.Background()
	ev, err := store.GetEvidence(ctx, evidenceID)
	if err != nil {
		return fmt.Errorf("loading evidence %s: %w", evidenceID, err)
	}

	// Load the collection attestation envelope.
	if ev.Attestation.DSSEEnvelopeRef == "" {
		return fmt.Errorf("evidence %s has no attestation", evidenceID)
	}

	envelopeJSON, err := store.GetAttestation(ctx, ev.Attestation.DSSEEnvelopeRef)
	if err != nil {
		return fmt.Errorf("loading attestation: %w", err)
	}

	var collEnvelope attestation.DSSEEnvelope
	if err := json.Unmarshal(envelopeJSON, &collEnvelope); err != nil {
		return fmt.Errorf("unmarshaling collection envelope: %w", err)
	}

	// Build the attestation chain.
	chain := attestation.AttestationChain{
		Evidence:           *ev,
		CollectionEnvelope: &collEnvelope,
	}

	// Write attestation chain JSON.
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	chainPath := filepath.Join(outputDir, fmt.Sprintf("attestation-chain-%s.json", evidenceID))
	chainJSON, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling attestation chain: %w", err)
	}
	if err := os.WriteFile(chainPath, chainJSON, 0644); err != nil {
		return fmt.Errorf("writing attestation chain: %w", err)
	}

	// Export the public key.
	keyDir, _ := cmd.Flags().GetString("key-dir")
	if keyDir == "" {
		keyDir = expandPath(cfg.KeyPath)
	}

	privKeyFile := filepath.Join(keyDir, "ocean-ed25519.key")
	signer, err := attestation.LoadSigner(privKeyFile)
	if err != nil {
		return fmt.Errorf("loading signing key: %w", err)
	}

	pubKeyPath := filepath.Join(outputDir, "ocean-public-key.pem")
	if err := attestation.ExportPublicKey(signer, pubKeyPath); err != nil {
		return fmt.Errorf("exporting public key: %w", err)
	}

	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Attestation chain exported for evidence %s\n", evidenceID)
	fmt.Fprintf(w, "  Chain:      %s\n", chainPath)
	fmt.Fprintf(w, "  Public key: %s\n", pubKeyPath)
	fmt.Fprintf(w, "\nTo verify with a third-party tool:\n")
	fmt.Fprintf(w, "  ocean verify-provenance standalone --chain %s --public-key %s\n", chainPath, pubKeyPath)

	return nil
}
