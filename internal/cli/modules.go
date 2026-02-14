package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/grcengineering/ocean/internal/module"
	awscollector "github.com/grcengineering/ocean/modules/collectors/aws"
	githubcollector "github.com/grcengineering/ocean/modules/collectors/github"
	mockcollector "github.com/grcengineering/ocean/modules/collectors/mock"
	oktacollector "github.com/grcengineering/ocean/modules/collectors/okta"
	awstester "github.com/grcengineering/ocean/modules/testers/aws"
	githubtester "github.com/grcengineering/ocean/modules/testers/github"
	mocktester "github.com/grcengineering/ocean/modules/testers/mock"
	oktatester "github.com/grcengineering/ocean/modules/testers/okta"
)

var moduleTypeFilter string

// buildDefaultRegistry creates a registry with all known modules registered.
func buildDefaultRegistry() *module.Registry {
	reg := module.NewRegistry()
	mockcollector.RegisterAll(reg)
	mocktester.RegisterAll(reg)
	oktacollector.RegisterAll(reg)
	oktatester.RegisterAll(reg)
	awscollector.RegisterAll(reg)
	awstester.RegisterAll(reg)
	githubcollector.RegisterAll(reg)
	githubtester.RegisterAll(reg)
	return reg
}

var modulesCmd = &cobra.Command{
	Use:   "modules",
	Short: "Manage and inspect collector and tester modules",
	Long: `Manage and inspect collector and tester modules available in OCEAN.

Use 'ocean modules list' to see all registered modules, or
'ocean modules validate <id>' to validate a specific module.`,
}

// --- T117-T118: ocean modules list [--type <type>] ---

var modulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered modules with their metadata",
	Long: `List all registered collector and tester modules, showing their ID,
version, type, source system, and safety classification.

Use --type to filter by module type:
  ocean modules list --type collector
  ocean modules list --type tester`,
	RunE: func(cmd *cobra.Command, args []string) error {
		reg := buildDefaultRegistry()

		var infos []module.ModuleInfo
		if moduleTypeFilter != "" {
			if moduleTypeFilter != "collector" && moduleTypeFilter != "tester" {
				return fmt.Errorf("invalid module type %q: must be 'collector' or 'tester'", moduleTypeFilter)
			}
			infos = reg.ListByType(moduleTypeFilter)
		} else {
			infos = reg.ListModules()
		}

		if len(infos) == 0 {
			cmd.Println("No modules found.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tVERSION\tTYPE\tSOURCE SYSTEM\tSAFETY CLASS")
		fmt.Fprintln(w, "--\t-------\t----\t-------------\t------------")
		for _, info := range infos {
			safety := info.SafetyClassification
			if safety == "" {
				safety = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				info.ID, info.Version, info.Type, info.SourceSystem, safety)
		}
		w.Flush()

		return nil
	},
}

// --- T119: ocean modules validate <module_id> ---

var modulesValidateCmd = &cobra.Command{
	Use:   "validate <module_id>",
	Short: "Validate a module's configuration and metadata",
	Long: `Validate a specific module by its ID, checking all required fields
and configuration rules. Reports pass/fail with details for each check.

Exit code 0 on pass, 1 on failure.

Example:
  ocean modules validate mock.test
  ocean modules validate mock.safety_test`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		moduleID := args[0]
		reg := buildDefaultRegistry()

		m, err := reg.GetModule(moduleID)
		if err != nil {
			return fmt.Errorf("module %q not found in registry", moduleID)
		}

		var errs []module.ValidationError
		if t, ok := m.(module.Tester); ok {
			errs = module.ValidateTester(t)
		} else {
			errs = module.ValidateModule(m)
		}

		if len(errs) == 0 {
			cmd.Printf("PASS: module %q passed all validation checks.\n", moduleID)
			return nil
		}

		cmd.Printf("FAIL: module %q has %d validation error(s):\n", moduleID, len(errs))
		for i, e := range errs {
			cmd.Printf("  %d. [%s] %s\n", i+1, e.Field, e.Message)
		}

		os.Exit(1)
		return nil // unreachable, but required for the compiler
	},
}

func init() {
	modulesListCmd.Flags().StringVar(&moduleTypeFilter, "type", "", "filter by module type (collector or tester)")
	modulesCmd.AddCommand(modulesListCmd)
	modulesCmd.AddCommand(modulesValidateCmd)
}
