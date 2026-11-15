package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/Romstar/auth-chaser/pkg/types"
)

// WriteCSV writes findings as a spreadsheet-friendly CSV document.
func WriteCSV(w io.Writer, r *types.Report) error {
	cw := csv.NewWriter(w)
	header := []string{
		"target",
		"started_at",
		"finished_at",
		"duration_ms",
		"authorized",
		"tool_version",
		"packs",
		"check_id",
		"title",
		"category",
		"severity",
		"status",
		"summary",
		"evidence",
		"remediation",
		"pack",
		"protocol",
		"cwe",
		"pass_count",
		"fail_count",
		"warn_count",
		"skip_count",
		"error_count",
	}
	if err := cw.Write(header); err != nil {
		return err
	}

	packs := joinCSV(r.Packs)
	started := r.StartedAt.UTC().Format(time.RFC3339)
	finished := r.FinishedAt.UTC().Format(time.RFC3339)
	auth := strconv.FormatBool(r.Authorized)
	duration := strconv.FormatInt(r.DurationMS, 10)
	pass := strconv.Itoa(r.PassCount)
	fail := strconv.Itoa(r.FailCount)
	warn := strconv.Itoa(r.WarnCount)
	skip := strconv.Itoa(r.SkipCount)
	errc := strconv.Itoa(r.ErrorCount)

	if len(r.Findings) == 0 {
		row := []string{
			r.Target, started, finished, duration, auth, r.ToolVersion, packs,
			"", "", "", "", "", "", "", "", "", "", "",
			pass, fail, warn, skip, errc,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
		cw.Flush()
		return cw.Error()
	}

	for _, f := range r.Findings {
		row := []string{
			r.Target,
			started,
			finished,
			duration,
			auth,
			r.ToolVersion,
			packs,
			f.CheckID,
			f.Title,
			string(f.Category),
			string(f.Severity),
			string(f.Status),
			f.Summary,
			f.Evidence,
			f.Remediation,
			f.Pack,
			f.Protocol,
			f.CWE,
			pass,
			fail,
			warn,
			skip,
			errc,
		}
		if err := cw.Write(row); err != nil {
			return fmt.Errorf("write csv row: %w", err)
		}
	}
	cw.Flush()
	return cw.Error()
}

func joinCSV(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += ";" + parts[i]
	}
	return out
}
