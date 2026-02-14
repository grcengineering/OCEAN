package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/grcengineering/ocean/internal/attestation"
	"github.com/spf13/cobra"
)

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage cryptographic signing keys",
	Long: `Manage Ed25519 signing keys used for DSSE attestation envelopes.

Keys are stored in ~/.ocean/keys/ by default. Use --key-dir to override.`,
}

var keysGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new Ed25519 signing keypair",
	Long: `Generate a new Ed25519 keypair for signing evidence attestations.

The private key is saved with restrictive permissions (0600).
The public key can be shared freely for verification.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		keyDir, err := cmd.Flags().GetString("key-dir")
		if err != nil {
			return err
		}

		if keyDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("determining home directory: %w", err)
			}
			keyDir = filepath.Join(home, ".ocean", "keys")
		}

		pubPath, privPath, err := attestation.GenerateKeyPair(keyDir)
		if err != nil {
			return fmt.Errorf("generating keypair: %w", err)
		}

		signer, err := attestation.LoadSigner(privPath)
		if err != nil {
			return fmt.Errorf("loading generated key: %w", err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Keypair generated successfully.\n")
		fmt.Fprintf(cmd.OutOrStdout(), "  Public key:  %s\n", pubPath)
		fmt.Fprintf(cmd.OutOrStdout(), "  Private key: %s\n", privPath)
		fmt.Fprintf(cmd.OutOrStdout(), "  Key ID:      %s\n", signer.KeyID())
		return nil
	},
}

var keysShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show public key path and key ID",
	Long:  `Display the public key file path and key ID for the current signing key.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		keyDir, err := cmd.Flags().GetString("key-dir")
		if err != nil {
			return err
		}

		if keyDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("determining home directory: %w", err)
			}
			keyDir = filepath.Join(home, ".ocean", "keys")
		}

		privPath := filepath.Join(keyDir, "ocean-ed25519.key")
		pubPath := filepath.Join(keyDir, "ocean-ed25519.pub")

		if _, err := os.Stat(privPath); os.IsNotExist(err) {
			return fmt.Errorf("no signing key found in %s (run 'ocean keys generate' first)", keyDir)
		}

		signer, err := attestation.LoadSigner(privPath)
		if err != nil {
			return fmt.Errorf("loading signing key: %w", err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Public key:  %s\n", pubPath)
		fmt.Fprintf(cmd.OutOrStdout(), "Key ID:      %s\n", signer.KeyID())
		return nil
	},
}

func init() {
	keysCmd.PersistentFlags().String("key-dir", "", "directory for key storage (default: ~/.ocean/keys/)")
	keysCmd.AddCommand(keysGenerateCmd)
	keysCmd.AddCommand(keysShowCmd)
}
