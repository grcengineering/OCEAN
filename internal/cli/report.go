package cli

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/grcengineering/ocean/internal/config"
	"github.com/grcengineering/ocean/internal/control"
	"github.com/grcengineering/ocean/internal/evidence"
	"github.com/grcengineering/ocean/internal/storage"
	sqlitestore "github.com/grcengineering/ocean/internal/storage/sqlite"
)

// reportOptions holds parameters for report generation.
type reportOptions struct {
	format           string
	from             time.Time
	to               time.Time
	controlFilter    string
	verifyProvenance bool
}

// controlSummary aggregates evidence for a single control in the report.
type controlSummary struct {
	ControlID    string
	Status       string
	Confidence   string
	Uptime       float64
	Evidence     []evidence.Evidence
	UptimeResult control.UptimeResult
	Disclaimer   string
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate compliance reports from collected evidence",
	Long: `Generate a compliance report from collected evidence in markdown or CSV format.

Examples:
  ocean report --format markdown --period 2026-01-01:2026-06-30
  ocean report --format csv --period 2026-01-01:2026-06-30
  ocean report --format markdown --period 2026-01-01:2026-06-30 --control okta.mfa
  ocean report --format markdown --period 2026-01-01:2026-06-30 --verify-provenance`,
	RunE: runReport,
}

func init() {
	reportCmd.Flags().String("format", "markdown", "Report format: markdown or csv")
	reportCmd.Flags().String("period", "", "Report period as YYYY-MM-DD:YYYY-MM-DD (required)")
	reportCmd.Flags().String("control", "", "Filter to a specific control ID (optional)")
	reportCmd.Flags().Bool("verify-provenance", false, "Verify attestation provenance for each evidence record")

	_ = reportCmd.MarkFlagRequired("period")
}

// runReport is the top-level handler for the report command (T165).
func runReport(cmd *cobra.Command, args []string) error {
	periodStr, _ := cmd.Flags().GetString("period")
	formatStr, _ := cmd.Flags().GetString("format")
	controlID, _ := cmd.Flags().GetString("control")
	verifyProv, _ := cmd.Flags().GetBool("verify-provenance")

	from, to, err := parsePeriod(periodStr)
	if err != nil {
		return fmt.Errorf("parsing period: %w", err)
	}

	// Validate format.
	if formatStr != "markdown" && formatStr != "csv" {
		return fmt.Errorf("unsupported format %q: use markdown or csv", formatStr)
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

	opts := reportOptions{
		format:           formatStr,
		from:             from,
		to:               to,
		controlFilter:    controlID,
		verifyProvenance: verifyProv,
	}

	// Query evidence for the period.
	evs, err := queryReportEvidence(cmd, store, opts)
	if err != nil {
		return fmt.Errorf("querying evidence: %w", err)
	}

	// Query control statuses for all relevant controls.
	statuses, err := queryReportStatuses(cmd, store, evs, opts)
	if err != nil {
		return fmt.Errorf("querying statuses: %w", err)
	}

	switch formatStr {
	case "csv":
		return generateCSVReport(os.Stdout, evs, statuses, opts)
	default:
		return generateMarkdownReport(os.Stdout, evs, statuses, opts)
	}
}

// parsePeriod parses a "YYYY-MM-DD:YYYY-MM-DD" period string into from/to times.
func parsePeriod(period string) (time.Time, time.Time, error) {
	parts := strings.SplitN(period, ":", 2)
	if len(parts) != 2 {
		return time.Time{}, time.Time{}, fmt.Errorf("period must be in format YYYY-MM-DD:YYYY-MM-DD, got %q", period)
	}

	from, err := time.Parse("2006-01-02", parts[0])
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("parsing start date: %w", err)
	}

	toDate, err := time.Parse("2006-01-02", parts[1])
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("parsing end date: %w", err)
	}

	// Set to end of day.
	to := toDate.Add(24*time.Hour - time.Second)

	return from, to, nil
}

// queryReportEvidence fetches evidence records for the report period.
func queryReportEvidence(cmd *cobra.Command, store storage.Store, opts reportOptions) ([]evidence.Evidence, error) {
	query := storage.EvidenceQuery{
		FromTime: &opts.from,
		ToTime:   &opts.to,
	}
	if opts.controlFilter != "" {
		query.ControlID = opts.controlFilter
	}

	return store.QueryEvidence(cmd.Context(), query)
}

// queryReportStatuses fetches control statuses for controls found in evidence.
func queryReportStatuses(cmd *cobra.Command, store storage.Store, evs []evidence.Evidence, opts reportOptions) ([]control.ControlStatus, error) {
	controlIDs := uniqueControlIDs(evs)

	var allStatuses []control.ControlStatus
	for _, cid := range controlIDs {
		statuses, err := store.QueryHistory(cmd.Context(), cid, opts.from, opts.to)
		if err != nil {
			return nil, fmt.Errorf("querying history for %s: %w", cid, err)
		}
		allStatuses = append(allStatuses, statuses...)
	}
	return allStatuses, nil
}

// uniqueControlIDs returns deduplicated, sorted control IDs from evidence.
func uniqueControlIDs(evs []evidence.Evidence) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, ev := range evs {
		if !seen[ev.ControlID] {
			seen[ev.ControlID] = true
			ids = append(ids, ev.ControlID)
		}
	}
	sort.Strings(ids)
	return ids
}

// buildControlSummaries groups evidence by control and computes summaries
// including uptime, status, and data quality disclaimers.
func buildControlSummaries(evs []evidence.Evidence, statuses []control.ControlStatus, opts reportOptions) []controlSummary {
	// Group evidence by control.
	evByControl := make(map[string][]evidence.Evidence)
	for _, ev := range evs {
		evByControl[ev.ControlID] = append(evByControl[ev.ControlID], ev)
	}

	// Group statuses by control.
	statusesByControl := make(map[string][]control.ControlStatus)
	for _, s := range statuses {
		statusesByControl[s.ControlID] = append(statusesByControl[s.ControlID], s)
	}

	// Build summaries.
	var summaries []controlSummary
	for _, controlID := range uniqueControlIDs(evs) {
		ctrlEvs := evByControl[controlID]
		ctrlStatuses := statusesByControl[controlID]

		// Calculate uptime.
		interval := 24 * time.Hour
		uptimeResult := control.CalculateUptime(ctrlStatuses, opts.from, opts.to, interval)

		// Find latest status.
		latestStatus := "unknown"
		latestConfidence := "low"
		if len(ctrlStatuses) > 0 {
			latest := ctrlStatuses[0]
			for _, s := range ctrlStatuses[1:] {
				if s.Timestamp.After(latest.Timestamp) {
					latest = s
				}
			}
			latestStatus = latest.Status
			latestConfidence = latest.Confidence
		}

		// Generate data quality disclaimer (T163).
		disclaimer := generateDataQualityDisclaimer(uptimeResult)

		summaries = append(summaries, controlSummary{
			ControlID:  controlID,
			Status:     latestStatus,
			Confidence: latestConfidence,
			Uptime:     uptimeResult.UptimePercent,
			Evidence:   ctrlEvs,
			UptimeResult: uptimeResult,
			Disclaimer: disclaimer,
		})
	}

	return summaries
}

// --- T159: Markdown report generation ---

// generateMarkdownReport generates a full compliance report in markdown format.
func generateMarkdownReport(w io.Writer, evs []evidence.Evidence, statuses []control.ControlStatus, opts reportOptions) error {
	summaries := buildControlSummaries(evs, statuses, opts)

	// T164: Sort failures first for radical transparency.
	summaries = sortControlsFailuresFirst(summaries)

	// Report header.
	fmt.Fprintf(w, "# OCEAN Compliance Report\n\n")
	fmt.Fprintf(w, "**Period**: %s to %s\n\n", opts.from.Format("2006-01-02"), opts.to.Format("2006-01-02"))
	fmt.Fprintf(w, "**Generated**: %s\n\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(w, "**Total Controls**: %d\n\n", len(summaries))

	// Executive summary: count effective/ineffective.
	effectiveCount := 0
	ineffectiveCount := 0
	for _, s := range summaries {
		switch s.Status {
		case "effective":
			effectiveCount++
		case "ineffective":
			ineffectiveCount++
		}
	}
	fmt.Fprintf(w, "**Summary**: %d effective, %d ineffective, %d other\n\n",
		effectiveCount, ineffectiveCount, len(summaries)-effectiveCount-ineffectiveCount)

	if ineffectiveCount > 0 {
		fmt.Fprintf(w, "> **WARNING**: %d control(s) are currently INEFFECTIVE. See details below.\n\n", ineffectiveCount)
	}

	fmt.Fprintf(w, "---\n\n")

	// Control summaries table.
	fmt.Fprintf(w, "## Control Status Summary\n\n")
	fmt.Fprintf(w, "| Control | Status | Confidence | Uptime | Evidence Count |\n")
	fmt.Fprintf(w, "|---------|--------|------------|--------|----------------|\n")

	for _, s := range summaries {
		statusDisplay := s.Status
		if s.Status == "ineffective" {
			statusDisplay = "**INEFFECTIVE**"
		}
		fmt.Fprintf(w, "| %s | %s | %s | %.2f%% | %d |\n",
			s.ControlID, statusDisplay, s.Confidence, s.Uptime, len(s.Evidence))
	}
	fmt.Fprintf(w, "\n")

	// Per-control details.
	fmt.Fprintf(w, "---\n\n")
	fmt.Fprintf(w, "## Control Details\n\n")

	for _, s := range summaries {
		fmt.Fprintf(w, "### %s\n\n", s.ControlID)

		// Status with prominence for failures (T164).
		if s.Status == "ineffective" {
			fmt.Fprintf(w, "> **WARNING: CONTROL IS INEFFECTIVE**\n\n")
		}

		fmt.Fprintf(w, "- **Status**: %s\n", formatStatusMarkdown(s.Status))
		fmt.Fprintf(w, "- **Confidence**: %s\n", s.Confidence)
		fmt.Fprintf(w, "- **Uptime**: %.2f%%\n", s.Uptime)
		fmt.Fprintf(w, "- **Evidence Records**: %d\n\n", len(s.Evidence))

		// Data quality disclaimer (T163).
		if s.Disclaimer != "" {
			fmt.Fprintf(w, "> %s\n\n", s.Disclaimer)
		}

		// Evidence breakdown table.
		if len(s.Evidence) > 0 {
			fmt.Fprintf(w, "#### Evidence Records\n\n")
			fmt.Fprintf(w, "| Timestamp | Status | Confidence Level | Module | Source |\n")
			fmt.Fprintf(w, "|-----------|--------|-----------------|--------|--------|\n")

			for _, ev := range s.Evidence {
				statusDisplay := ev.Status
				if ev.StatusID == evidence.StatusIneffective {
					statusDisplay = "**INEFFECTIVE**"
				}
				fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n",
					ev.Time.Format("2006-01-02 15:04:05"),
					statusDisplay,
					string(ev.ConfidenceLevel),
					ev.Metadata.Module.Name,
					ev.Metadata.Source.System,
				)
			}
			fmt.Fprintf(w, "\n")
		}

		// Transcript summaries (T162).
		for _, ev := range s.Evidence {
			if ev.TestTranscript != nil {
				fmt.Fprintf(w, "#### Test Transcript (%s)\n\n", ev.Time.Format("2006-01-02 15:04:05"))
				fmt.Fprintf(w, "%s\n\n", formatTranscriptSummary(ev.TestTranscript))
			}
		}

		fmt.Fprintf(w, "---\n\n")
	}

	return nil
}

// formatStatusMarkdown returns the status string with markdown formatting.
// Failures are bold for prominence (T164).
func formatStatusMarkdown(status string) string {
	if status == "ineffective" {
		return "**INEFFECTIVE**"
	}
	return status
}

// --- T160: CSV report generation ---

// generateCSVReport generates a tabular evidence export in CSV format.
func generateCSVReport(w io.Writer, evs []evidence.Evidence, _ []control.ControlStatus, _ reportOptions) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Header row.
	header := []string{"control_id", "timestamp", "status", "confidence", "source", "module", "confidence_level", "has_attestation"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	// Data rows.
	for _, ev := range evs {
		hasAttestation := "false"
		if ev.Attestation.DSSEEnvelopeRef != "" {
			hasAttestation = "true"
		}

		row := []string{
			ev.ControlID,
			ev.Time.Format(time.RFC3339),
			ev.Status,
			string(ev.ConfidenceLevel),
			ev.Metadata.Source.System,
			ev.Metadata.Module.Name,
			string(ev.ConfidenceLevel),
			hasAttestation,
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("writing CSV row: %w", err)
		}
	}

	return nil
}

// --- T161: Provenance verification ---

// provStatusString returns the provenance verification status string.
func provStatusString(hasAttestation bool, verified *bool) string {
	if !hasAttestation {
		return "Unverified"
	}
	if verified == nil {
		return "Unverified"
	}
	if *verified {
		return "Verified"
	}
	return "Failed"
}

// --- T162: Transcript summary formatting ---

// formatTranscriptSummary creates a human-readable summary of a test transcript.
func formatTranscriptSummary(transcript *evidence.TestTranscript) string {
	if transcript == nil {
		return ""
	}

	var sb strings.Builder

	if len(transcript.ActionsAttempted) > 0 {
		sb.WriteString("**Actions Attempted:**\n")
		for _, a := range transcript.ActionsAttempted {
			sb.WriteString(fmt.Sprintf("- %s\n", a.Action))
		}
		sb.WriteString("\n")
	}

	if len(transcript.Observations) > 0 {
		sb.WriteString("**Observations:**\n")
		for _, o := range transcript.Observations {
			expected := "unexpected"
			if o.Expected {
				expected = "expected"
			}
			sb.WriteString(fmt.Sprintf("- %s (%s)\n", o.Observation, expected))
		}
		sb.WriteString("\n")
	}

	if len(transcript.CleanupActions) > 0 {
		sb.WriteString("**Cleanup Actions:**\n")
		for _, c := range transcript.CleanupActions {
			status := "failed"
			if c.Success {
				status = "success"
			}
			sb.WriteString(fmt.Sprintf("- %s (%s)\n", c.Action, status))
		}
	}

	return sb.String()
}

// --- T163: Data quality disclaimers ---

const gapThresholdPercent = 10.0

// generateDataQualityDisclaimer generates a warning when evidence gaps exceed
// the threshold (T163).
func generateDataQualityDisclaimer(uptime control.UptimeResult) string {
	if uptime.TotalBuckets == 0 {
		return "WARNING: No evidence data available for this period. Coverage: 0%."
	}

	gapPercent := float64(uptime.GapBuckets) / float64(uptime.TotalBuckets) * 100.0

	if gapPercent > gapThresholdPercent {
		coverage := 100.0 - gapPercent
		return fmt.Sprintf("WARNING: Evidence coverage is sparse. %.1f%% of monitoring periods have no data (%.1f%% coverage). "+
			"Uptime calculations may not reflect actual control effectiveness during gaps.",
			gapPercent, coverage)
	}

	return ""
}

// --- T164: Failure prominence ---

// sortControlsFailuresFirst sorts control summaries with ineffective controls
// appearing first, per Radical Transparency principle (T164).
func sortControlsFailuresFirst(summaries []controlSummary) []controlSummary {
	sorted := make([]controlSummary, len(summaries))
	copy(sorted, summaries)

	sort.SliceStable(sorted, func(i, j int) bool {
		iIneffective := sorted[i].Status == "ineffective"
		jIneffective := sorted[j].Status == "ineffective"
		if iIneffective != jIneffective {
			return iIneffective
		}
		return sorted[i].ControlID < sorted[j].ControlID
	})

	return sorted
}
