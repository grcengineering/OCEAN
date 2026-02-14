package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/grcengineering/ocean/internal/attestation"
	"github.com/grcengineering/ocean/internal/config"
	"github.com/grcengineering/ocean/internal/module"
	sqlitestore "github.com/grcengineering/ocean/internal/storage/sqlite"
	awscollector "github.com/grcengineering/ocean/modules/collectors/aws"
	githubcollector "github.com/grcengineering/ocean/modules/collectors/github"
	mockcollector "github.com/grcengineering/ocean/modules/collectors/mock"
	oktacollector "github.com/grcengineering/ocean/modules/collectors/okta"
)

var collectCmd = &cobra.Command{
	Use:   "collect <module>",
	Short: "Run a collector module to gather passive evidence",
	Long: `Run a collector module by its ID to gather passive evidence from a source
system. Evidence is written to stdout in the requested format (json or yaml).

Example:
  ocean collect mock.test
  ocean collect mock.test --format yaml`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		moduleID := args[0]

		// Load configuration (T067: wire config loader).
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// Build the module registry and register available collectors.
		reg := module.NewRegistry()
		mockcollector.RegisterAll(reg)
		oktacollector.RegisterAll(reg)
		awscollector.RegisterAll(reg)
		githubcollector.RegisterAll(reg)

		// Execute the requested collector.
		executor := module.NewExecutor(reg)
		evidences, err := executor.ExecuteCollector(context.Background(), moduleID, nil)
		if err != nil {
			return fmt.Errorf("collection failed: %w", err)
		}

		if len(evidences) == 0 {
			cmd.Println("No evidence collected.")
			return nil
		}

		// Open SQLite store for persistence (T064: store evidence in SQLite).
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

		ctx := context.Background()

		// Write each evidence record to stdout and store in SQLite.
		for i := range evidences {
			ev := &evidences[i]

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

			// Still output to stdout as before.
			if err := PrintOutput(os.Stdout, ev, outputFormat); err != nil {
				return fmt.Errorf("output failed: %w", err)
			}
		}

		return nil
	},
}

// expandPath replaces a leading ~/ with the user's home directory.
func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[2:])
	}
	return p
}
