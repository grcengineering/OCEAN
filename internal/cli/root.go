package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version   = "dev"
	buildTime = "unknown"

	cfgFile      string
	verbose      bool
	outputFormat string
)

var rootCmd = &cobra.Command{
	Use:   "ocean",
	Short: "OCEAN — Open Control Evidence Acquisition Normalizer",
	Long: `OCEAN is the "Metasploit for GRC" — an open-source CLI tool for evidence
acquisition, active control testing, and normalization powering continuous
compliance monitoring.

It operates across four pillars:
  1. Passive Control Monitoring (Collectors)
  2. Active Control Testing (Testers)
  3. Flexible Evaluation Logic (CEL)
  4. Cryptographic Provenance (in-toto DSSE)`,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print OCEAN version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("ocean %s (built %s)\n", version, buildTime)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.ocean/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "format", "f", "json", "output format (json, yaml)")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(collectCmd)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(evaluateCmd)
	rootCmd.AddCommand(historyCmd)
	rootCmd.AddCommand(scheduleCmd)
	rootCmd.AddCommand(modulesCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(verifyProvenanceCmd)
	rootCmd.AddCommand(keysCmd)
	rootCmd.AddCommand(serveCmd)
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
