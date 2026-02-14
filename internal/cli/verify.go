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
	"github.com/grcengineering/ocean/internal/module"
	sqlitestore "github.com/grcengineering/ocean/internal/storage/sqlite"
	awscollector "github.com/grcengineering/ocean/modules/collectors/aws"
	githubcollector "github.com/grcengineering/ocean/modules/collectors/github"
	mockcollector "github.com/grcengineering/ocean/modules/collectors/mock"
	oktacollector "github.com/grcengineering/ocean/modules/collectors/okta"
	awstester "github.com/grcengineering/ocean/modules/testers/aws"
	githubtester "github.com/grcengineering/ocean/modules/testers/github"
	mocktester "github.com/grcengineering/ocean/modules/testers/mock"
	oktatester "github.com/grcengineering/ocean/modules/testers/okta"
)

var controlsDir string

var verifyCmd = &cobra.Command{
	Use:   "verify <control>",
	Short: "Verify a control's current status",
	Long: `Verify a control by running both passive collectors and active testers,
then evaluating the combined evidence to produce a unified control status.

Example:
  ocean verify mock.mfa_enforcement
  ocean verify mock.mfa_enforcement --controls-dir ./controls`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		controlID := args[0]

		// Load configuration.
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// Determine controls directory.
		ctrlDir := controlsDir
		if ctrlDir == "" {
			ctrlDir = cfg.ControlsDir
		}

		// Load all control definitions and find the requested one.
		allControls, err := control.LoadAllControls(ctrlDir)
		if err != nil {
			return fmt.Errorf("loading controls from %s: %w", ctrlDir, err)
		}

		var ctrl *control.Control
		for _, c := range allControls {
			if c.ID == controlID {
				ctrl = c
				break
			}
		}
		if ctrl == nil {
			return fmt.Errorf("control %q not found in %s", controlID, ctrlDir)
		}

		// Build the module registry and register available modules.
		reg := module.NewRegistry()
		mockcollector.RegisterAll(reg)
		mocktester.RegisterAll(reg)
		oktacollector.RegisterAll(reg)
		oktatester.RegisterAll(reg)
		awscollector.RegisterAll(reg)
		awstester.RegisterAll(reg)
		githubcollector.RegisterAll(reg)
		githubtester.RegisterAll(reg)

		// Create executor and verifier.
		executor := module.NewExecutor(reg)
		verifier := control.NewVerifier(reg, executor)

		// Run dual-mode verification.
		ctx := context.Background()
		result, err := verifier.VerifyControl(ctx, ctrl)
		if err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}

		// Open SQLite store for persistence.
		storagePath := expandPath(cfg.StoragePath)
		store, err := sqlitestore.Open(storagePath)
		if err != nil {
			return fmt.Errorf("opening storage: %w", err)
		}
		defer store.Close()

		// Attempt to load signer for attestation signing.
		keyPath := expandPath(cfg.KeyPath)
		privKeyFile := filepath.Join(keyPath, "ocean-ed25519.key")
		signer, signerErr := attestation.LoadSigner(privKeyFile)
		if signerErr != nil {
			log.Warn().Err(signerErr).Msg("No signing key available; evidence will be stored without attestation")
		}

		// Sign and store each evidence record.
		for i := range result.Evidences {
			ev := &result.Evidences[i]

			// Sign evidence if signer is available.
			var envelope *attestation.DSSEEnvelope
			if signer != nil {
				envelope, err = attestation.SignEvidence(ev, signer)
				if err != nil {
					log.Warn().Err(err).Str("evidence_id", ev.ID.String()).Msg("Failed to sign evidence")
				}
			}

			// Store evidence in SQLite.
			if err := store.StoreEvidence(ctx, *ev); err != nil {
				return fmt.Errorf("storing evidence: %w", err)
			}

			// Store attestation envelope if signing succeeded.
			if envelope != nil {
				envelopeJSON, err := json.Marshal(envelope)
				if err != nil {
					return fmt.Errorf("marshaling envelope: %w", err)
				}
				if err := store.StoreAttestation(ctx, ev.Attestation.DSSEEnvelopeRef, envelopeJSON); err != nil {
					return fmt.Errorf("storing attestation: %w", err)
				}
			}
		}

		// Store the ControlStatus in SQLite (T089).
		if err := store.StoreControlStatus(ctx, *result.Status); err != nil {
			return fmt.Errorf("storing control status: %w", err)
		}

		// Output the verification result.
		if err := PrintOutput(os.Stdout, result, outputFormat); err != nil {
			return fmt.Errorf("output failed: %w", err)
		}

		return nil
	},
}

func init() {
	verifyCmd.Flags().StringVar(&controlsDir, "controls-dir", "", "directory containing control definitions (default from config)")
}
