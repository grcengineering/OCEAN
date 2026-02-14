package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/grcengineering/ocean/internal/config"
	"github.com/grcengineering/ocean/internal/control"
	sqlitestore "github.com/grcengineering/ocean/internal/storage/sqlite"
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "View control status history and uptime metrics",
	Long: `Display the historical status of a control over time, including
uptime percentage calculations and gap detection.

Example:
  ocean history --control mock.test --days 7
  ocean history --control mock.test --from 2026-01-01 --to 2026-01-31`,
	RunE: runHistory,
}

func init() {
	historyCmd.Flags().String("control", "", "Control ID to query (required)")
	historyCmd.Flags().Int("days", 7, "Number of days to look back")
	historyCmd.Flags().String("from", "", "Start date (YYYY-MM-DD)")
	historyCmd.Flags().String("to", "", "End date (YYYY-MM-DD, default today)")

	_ = historyCmd.MarkFlagRequired("control")
}

// historyEntry represents a single entry in the history output, including
// gap indicators for periods with no evidence (T066).
type historyEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Status     string    `json:"status"`
	Confidence string    `json:"confidence"`
}

// historyOutput is the full JSON output for the history command.
type historyOutput struct {
	ControlID          string         `json:"control_id"`
	From               time.Time      `json:"from"`
	To                 time.Time      `json:"to"`
	UptimePercent      float64        `json:"uptime_percent"`
	TotalBuckets       int            `json:"total_buckets"`
	EffectiveBuckets   int            `json:"effective_buckets"`
	IneffectiveBuckets int            `json:"ineffective_buckets"`
	GapBuckets         int            `json:"gap_buckets"`
	Entries            []historyEntry `json:"entries"`
}

func runHistory(cmd *cobra.Command, args []string) error {
	controlID, _ := cmd.Flags().GetString("control")
	days, _ := cmd.Flags().GetInt("days")
	fromStr, _ := cmd.Flags().GetString("from")
	toStr, _ := cmd.Flags().GetString("to")

	// Load configuration (T067: wire config loader to storage).
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Determine time range.
	now := time.Now().UTC()
	var from, to time.Time

	if toStr != "" {
		to, err = time.Parse("2006-01-02", toStr)
		if err != nil {
			return fmt.Errorf("parsing --to date: %w", err)
		}
		// Set to end of day.
		to = to.Add(24*time.Hour - time.Nanosecond)
	} else {
		to = now
	}

	if fromStr != "" {
		from, err = time.Parse("2006-01-02", fromStr)
		if err != nil {
			return fmt.Errorf("parsing --from date: %w", err)
		}
	} else {
		from = to.Truncate(24*time.Hour).Add(-time.Duration(days) * 24 * time.Hour)
	}

	// Open SQLite store (T067: use config storage path).
	storagePath := expandPath(cfg.StoragePath)
	store, err := sqlitestore.Open(storagePath)
	if err != nil {
		return fmt.Errorf("opening storage: %w", err)
	}
	defer store.Close()

	// Query control status history.
	statuses, err := store.QueryHistory(cmd.Context(), controlID, from, to)
	if err != nil {
		return fmt.Errorf("querying history: %w", err)
	}

	// Calculate uptime with daily buckets.
	interval := 24 * time.Hour
	uptimeResult := control.CalculateUptime(statuses, from, to, interval)

	// Build output entries with gap indication (T066).
	entries := buildHistoryEntries(statuses, from, to, interval)

	output := historyOutput{
		ControlID:          controlID,
		From:               from,
		To:                 to,
		UptimePercent:      uptimeResult.UptimePercent,
		TotalBuckets:       uptimeResult.TotalBuckets,
		EffectiveBuckets:   uptimeResult.EffectiveBuckets,
		IneffectiveBuckets: uptimeResult.IneffectiveBuckets,
		GapBuckets:         uptimeResult.GapBuckets,
		Entries:            entries,
	}

	return PrintOutput(os.Stdout, output, outputFormat)
}

// buildHistoryEntries creates a list of history entries with gap markers for
// buckets that have no control status data (T066: gap indication).
func buildHistoryEntries(statuses []control.ControlStatus, from, to time.Time, interval time.Duration) []historyEntry {
	if !from.Before(to) || interval <= 0 {
		return nil
	}

	// Index statuses by bucket for efficient lookup.
	type bucketKey struct {
		year  int
		month time.Month
		day   int
	}

	statusByBucket := make(map[bucketKey]*control.ControlStatus)
	for i := range statuses {
		s := &statuses[i]
		// Determine which bucket this status belongs to.
		bucketStart := from
		for bucketStart.Add(interval).Before(s.Timestamp) || bucketStart.Add(interval).Equal(s.Timestamp) {
			bucketStart = bucketStart.Add(interval)
			if !bucketStart.Before(to) {
				break
			}
		}
		key := bucketKey{bucketStart.Year(), bucketStart.Month(), bucketStart.Day()}
		existing, ok := statusByBucket[key]
		if !ok || s.Timestamp.After(existing.Timestamp) {
			statusByBucket[key] = s
		}
	}

	var entries []historyEntry
	for t := from; t.Before(to); t = t.Add(interval) {
		key := bucketKey{t.Year(), t.Month(), t.Day()}
		if s, ok := statusByBucket[key]; ok {
			entries = append(entries, historyEntry{
				Timestamp:  s.Timestamp,
				Status:     s.Status,
				Confidence: s.Confidence,
			})
		} else {
			// Gap: no evidence for this bucket (T066).
			entries = append(entries, historyEntry{
				Timestamp:  t,
				Status:     "gap",
				Confidence: "none",
			})
		}
	}

	return entries
}
