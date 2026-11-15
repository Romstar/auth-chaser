// Package report formats chase reports for humans and machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Romstar/auth-chaser/pkg/types"
)

// WriteJSON writes the report as indented JSON.
func WriteJSON(w io.Writer, r *types.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes a concise human-readable summary.
func WriteText(w io.Writer, r *types.Report) error {
	var b strings.Builder
	b.WriteString("auth-chaser report\n")
	b.WriteString(strings.Repeat("=", 48) + "\n")
	fmt.Fprintf(&b, "Target:      %s\n", r.Target)
	fmt.Fprintf(&b, "Started:     %s\n", r.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "Duration:    %dms\n", r.DurationMS)
	fmt.Fprintf(&b, "Authorized:  %v\n", r.Authorized)
	fmt.Fprintf(&b, "Version:     %s\n", r.ToolVersion)
	fmt.Fprintf(&b, "Summary:     pass=%d fail=%d warn=%d skip=%d error=%d\n",
		r.PassCount, r.FailCount, r.WarnCount, r.SkipCount, r.ErrorCount)
	b.WriteString(strings.Repeat("-", 48) + "\n")

	for _, f := range r.Findings {
		fmt.Fprintf(&b, "[%s] %-7s %-10s %s\n",
			strings.ToUpper(string(f.Status)),
			f.Severity,
			f.Category,
			f.Title,
		)
		fmt.Fprintf(&b, "  %s\n", f.Summary)
		if f.Evidence != "" {
			fmt.Fprintf(&b, "  evidence: %s\n", f.Evidence)
		}
		if f.Remediation != "" {
			fmt.Fprintf(&b, "  fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}

	_, err := io.WriteString(w, b.String())
	return err
}
