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
	"github.com/grcengineering/ocean/internal/module"
	sqlitestore "github.com/grcengineering/ocean/internal/storage/sqlite"
	awstester "github.com/grcengineering/ocean/modules/testers/aws"
	githubtester "github.com/grcengineering/ocean/modules/testers/github"
	mocktester "github.com/grcengineering/ocean/modules/testers/mock"
	oktatester "github.com/grcengineering/ocean/modules/testers/okta"
)

var targetEnv string

var testCmd = &cobra.Command{
	Use:   "test <module>",
	Short: "Run a tester module for active control verification",
	Long: `Run a tester module by its ID to perform active control verification.
Evidence is produced at the active_verification confidence level with a full
test transcript documenting all actions, observations, and cleanup steps.

The --target flag controls which environment scope the test runs against.
Safety classification enforcement prevents dangerous tests from running
in inappropriate environments (e.g., destructive tests in production).

Example:
  ocean test mock.safety_test
  ocean test mock.safety_test --target staging
  ocean test mock.safety_test --format yaml`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		moduleID := args[0]

		// Load configuration.
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// Build the module registry and register available testers.
		reg := module.NewRegistry()
		mocktester.RegisterAll(reg)
		oktatester.RegisterAll(reg)
		awstester.RegisterAll(reg)
		githubtester.RegisterAll(reg)

		// Parse target environment scope.
		target := module.EnvironmentScope(targetEnv)
		if !target.Valid() {
			return fmt.Errorf("invalid target environment %q: must be production, staging, or isolated", targetEnv)
		}

		// Build test configuration.
		testCfg := &module.TestConfig{
			TargetEnvironment: target,
			Authorizer:        &module.AutoAuthorizer{},
		}

		// Execute the requested tester through the full safety pipeline.
		executor := module.NewExecutor(reg)
		evidences, err := executor.ExecuteTester(context.Background(), moduleID, testCfg)
		if err != nil {
			return fmt.Errorf("test failed: %w", err)
		}

		if len(evidences) == 0 {
			cmd.Println("No evidence produced.")
			return nil
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

			// Output to stdout.
			if err := PrintOutput(os.Stdout, ev, outputFormat); err != nil {
				return fmt.Errorf("output failed: %w", err)
			}
		}

		return nil
	},
}

func init() {
	testCmd.Flags().StringVar(&targetEnv, "target", "production", "target environment scope (production, staging, isolated)")
}
