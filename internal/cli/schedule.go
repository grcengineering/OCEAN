package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/grcengineering/ocean/internal/config"
	"github.com/grcengineering/ocean/internal/scheduler"
	sqlitestore "github.com/grcengineering/ocean/internal/storage/sqlite"
)

var scheduleCmd = &cobra.Command{
	Use:   "schedule",
	Short: "Manage scheduled evidence collection jobs",
	Long: `Manage recurring evidence collection schedules. Schedules
run collectors and testers on a cron expression and store results.

Subcommands:
  add     Create a new schedule
  list    List all schedules
  remove  Remove a schedule by ID
  status  View schedule details and recent runs`,
}

// --- schedule add ---

var scheduleAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Create a new scheduled evidence collection job",
	Long: `Create a schedule that runs modules on a cron expression.

Examples:
  ocean schedule add --cron "*/30 * * * *" --modules mock-collector-a
  ocean schedule add --cron "0 * * * *" --control mock.mfa --modules mock-collector-a,mock-tester-b --max-safety observable`,
	RunE: runScheduleAdd,
}

func init() {
	scheduleAddCmd.Flags().String("cron", "", "Cron expression (required)")
	scheduleAddCmd.Flags().String("control", "", "Control ID to associate with this schedule")
	scheduleAddCmd.Flags().String("modules", "", "Comma-separated module IDs to run (required)")
	scheduleAddCmd.Flags().String("max-safety", "safe", "Maximum safety level for testers (safe, observable, reversible)")
	scheduleAddCmd.Flags().String("env", "production", "Target environment scope (production, staging, isolated)")
	scheduleAddCmd.Flags().Bool("catch-up", false, "Execute missed runs on startup")

	_ = scheduleAddCmd.MarkFlagRequired("cron")
	_ = scheduleAddCmd.MarkFlagRequired("modules")

	scheduleCmd.AddCommand(scheduleAddCmd)
	scheduleCmd.AddCommand(scheduleListCmd)
	scheduleCmd.AddCommand(scheduleRemoveCmd)
	scheduleCmd.AddCommand(scheduleStatusCmd)
}

func runScheduleAdd(cmd *cobra.Command, args []string) error {
	cronExpr, _ := cmd.Flags().GetString("cron")
	controlID, _ := cmd.Flags().GetString("control")
	modulesStr, _ := cmd.Flags().GetString("modules")
	maxSafety, _ := cmd.Flags().GetString("max-safety")
	env, _ := cmd.Flags().GetString("env")
	catchUp, _ := cmd.Flags().GetBool("catch-up")

	modules := strings.Split(modulesStr, ",")
	for i := range modules {
		modules[i] = strings.TrimSpace(modules[i])
	}

	// Validate max-safety.
	validSafety := map[string]bool{"safe": true, "observable": true, "reversible": true}
	if !validSafety[maxSafety] {
		return fmt.Errorf("invalid --max-safety %q: must be safe, observable, or reversible (destructive not allowed in schedules)", maxSafety)
	}

	// Validate env.
	validEnv := map[string]bool{"production": true, "staging": true, "isolated": true}
	if !validEnv[env] {
		return fmt.Errorf("invalid --env %q: must be production, staging, or isolated", env)
	}

	// Validate cron expression.
	testScheduler := scheduler.NewScheduler()
	testSched := scheduler.Schedule{
		ID:       "validate",
		CronExpr: cronExpr,
		Modules:  modules,
		Enabled:  true,
	}
	if err := testScheduler.Add(testSched, nil); err != nil {
		return fmt.Errorf("invalid cron expression: %w", err)
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	storagePath := expandPath(cfg.StoragePath)
	store, err := sqlitestore.Open(storagePath)
	if err != nil {
		return fmt.Errorf("opening storage: %w", err)
	}
	defer store.Close()

	now := time.Now()
	sched := scheduler.Schedule{
		ID:               uuid.New().String(),
		ControlID:        controlID,
		CronExpr:         cronExpr,
		Modules:          modules,
		MaxSafetyLevel:   maxSafety,
		EnvironmentScope: env,
		Enabled:          true,
		CatchUp:          catchUp,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := store.StoreSchedule(cmd.Context(), sched); err != nil {
		return fmt.Errorf("storing schedule: %w", err)
	}

	output := map[string]interface{}{
		"id":               sched.ID,
		"control_id":       sched.ControlID,
		"cron_expr":        sched.CronExpr,
		"modules":          sched.Modules,
		"max_safety_level": sched.MaxSafetyLevel,
		"environment":      sched.EnvironmentScope,
		"catch_up":         sched.CatchUp,
		"enabled":          sched.Enabled,
		"created_at":       sched.CreatedAt,
	}

	return PrintOutput(os.Stdout, output, outputFormat)
}

// --- schedule list ---

var scheduleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all scheduled evidence collection jobs",
	RunE:  runScheduleList,
}

type scheduleListEntry struct {
	ID               string     `json:"id"`
	ControlID        string     `json:"control_id,omitempty"`
	CronExpr         string     `json:"cron_expr"`
	Modules          []string   `json:"modules"`
	MaxSafetyLevel   string     `json:"max_safety_level"`
	EnvironmentScope string     `json:"environment_scope"`
	Enabled          bool       `json:"enabled"`
	LastRun          *time.Time `json:"last_run,omitempty"`
	NextRun          *time.Time `json:"next_run,omitempty"`
}

func runScheduleList(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	storagePath := expandPath(cfg.StoragePath)
	store, err := sqlitestore.Open(storagePath)
	if err != nil {
		return fmt.Errorf("opening storage: %w", err)
	}
	defer store.Close()

	schedules, err := store.ListSchedules(cmd.Context())
	if err != nil {
		return fmt.Errorf("listing schedules: %w", err)
	}

	entries := make([]scheduleListEntry, 0, len(schedules))
	for _, s := range schedules {
		entries = append(entries, scheduleListEntry{
			ID:               s.ID,
			ControlID:        s.ControlID,
			CronExpr:         s.CronExpr,
			Modules:          s.Modules,
			MaxSafetyLevel:   s.MaxSafetyLevel,
			EnvironmentScope: s.EnvironmentScope,
			Enabled:          s.Enabled,
			LastRun:          s.LastRun,
			NextRun:          s.NextRun,
		})
	}

	output := map[string]interface{}{
		"schedules": entries,
		"count":     len(entries),
	}

	return PrintOutput(os.Stdout, output, outputFormat)
}

// --- schedule remove ---

var scheduleRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove a scheduled job by ID",
	Long: `Remove a schedule and all its run history.

Example:
  ocean schedule remove --id <schedule-id>`,
	RunE: runScheduleRemove,
}

func init() {
	scheduleRemoveCmd.Flags().String("id", "", "Schedule ID to remove (required)")
	_ = scheduleRemoveCmd.MarkFlagRequired("id")
}

func runScheduleRemove(cmd *cobra.Command, args []string) error {
	schedID, _ := cmd.Flags().GetString("id")

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	storagePath := expandPath(cfg.StoragePath)
	store, err := sqlitestore.Open(storagePath)
	if err != nil {
		return fmt.Errorf("opening storage: %w", err)
	}
	defer store.Close()

	if err := store.DeleteSchedule(cmd.Context(), schedID); err != nil {
		return fmt.Errorf("deleting schedule: %w", err)
	}

	output := map[string]interface{}{
		"deleted": schedID,
		"status":  "ok",
	}

	return PrintOutput(os.Stdout, output, outputFormat)
}

// --- schedule status ---

var scheduleStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "View schedule details and recent run history",
	Long: `Show detailed information about a schedule including its configuration
and recent execution results.

Example:
  ocean schedule status --id <schedule-id>
  ocean schedule status --id <schedule-id> --runs 10`,
	RunE: runScheduleStatus,
}

func init() {
	scheduleStatusCmd.Flags().String("id", "", "Schedule ID to view (required)")
	scheduleStatusCmd.Flags().Int("runs", 5, "Number of recent runs to show")
	_ = scheduleStatusCmd.MarkFlagRequired("id")
}

func runScheduleStatus(cmd *cobra.Command, args []string) error {
	schedID, _ := cmd.Flags().GetString("id")
	runLimit, _ := cmd.Flags().GetInt("runs")

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	storagePath := expandPath(cfg.StoragePath)
	store, err := sqlitestore.Open(storagePath)
	if err != nil {
		return fmt.Errorf("opening storage: %w", err)
	}
	defer store.Close()

	sched, err := store.GetSchedule(cmd.Context(), schedID)
	if err != nil {
		return fmt.Errorf("getting schedule: %w", err)
	}

	runs, err := store.ListScheduleRuns(cmd.Context(), schedID, runLimit)
	if err != nil {
		return fmt.Errorf("listing schedule runs: %w", err)
	}

	output := map[string]interface{}{
		"schedule": sched,
		"runs":     runs,
	}

	return PrintOutput(os.Stdout, output, outputFormat)
}
