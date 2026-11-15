package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Romstar/auth-chaser/pkg/types"
)

// Narrative is a human-readable executive summary for designed reports.
type Narrative struct {
	Headline string
	Body     string
	Risk     string
}

// ChartSlice is one segment of a status or severity chart.
type ChartSlice struct {
	Label string
	Count int
	Color string // #RRGGBB
}

// BuildNarrative writes a clear executive summary from report totals.
func BuildNarrative(r *types.Report) Narrative {
	total := len(r.Findings)
	fails := r.FailCount + r.ErrorCount
	duration := formatDuration(r.DurationMS)

	headline := "Authentication verification completed"
	switch {
	case fails == 0 && r.WarnCount == 0:
		headline = "Authentication surface looks healthy"
	case fails == 0 && r.WarnCount > 0:
		headline = "Verification passed with warnings"
	case fails == 1:
		headline = "One authentication issue needs attention"
	default:
		headline = fmt.Sprintf("%d authentication issues need attention", fails)
	}

	var body strings.Builder
	fmt.Fprintf(&body,
		"auth-chaser verified %s in %s. The run covered %d check%s across %s.",
		r.Target,
		duration,
		total,
		plural(total),
		packPhrase(r.Packs),
	)
	fmt.Fprintf(&body,
		" Results: %d passed, %d failed, %d warned, %d skipped, %d errored.",
		r.PassCount, r.FailCount, r.WarnCount, r.SkipCount, r.ErrorCount,
	)
	if r.Authorized {
		body.WriteString(" The operator confirmed ownership or written authorization for this target.")
	}

	risk := "Low risk signal from this chase."
	crit := 0
	high := 0
	for _, f := range r.Findings {
		if f.Status != types.StatusFail && f.Status != types.StatusError {
			continue
		}
		switch f.Severity {
		case types.SeverityCritical:
			crit++
		case types.SeverityHigh:
			high++
		}
	}
	switch {
	case crit > 0:
		risk = fmt.Sprintf("High risk: %d critical failure%s require immediate remediation.", crit, plural(crit))
	case high > 0:
		risk = fmt.Sprintf("Elevated risk: %d high-severity failure%s need remediation before production.", high, plural(high))
	case fails > 0:
		risk = "Moderate risk: failures exist. Review remediation steps below."
	case r.WarnCount > 0:
		risk = "Watchlist: no failures, but warnings indicate hardening opportunities."
	}

	return Narrative{Headline: headline, Body: body.String(), Risk: risk}
}

func formatDuration(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	d := time.Duration(ms) * time.Millisecond
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return d.Round(time.Second).String()
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func packPhrase(packs []string) string {
	if len(packs) == 0 {
		return "default packs"
	}
	if len(packs) == 1 {
		return "pack " + packs[0]
	}
	return "packs " + strings.Join(packs, ", ")
}

// StatusSlices returns ordered status counts for charts.
func StatusSlices(r *types.Report) []ChartSlice {
	return []ChartSlice{
		{Label: "Pass", Count: r.PassCount, Color: "#1f8a5b"},
		{Label: "Fail", Count: r.FailCount, Color: "#c0392b"},
		{Label: "Warn", Count: r.WarnCount, Color: "#c47f17"},
		{Label: "Skip", Count: r.SkipCount, Color: "#6b7c8f"},
		{Label: "Error", Count: r.ErrorCount, Color: "#8e2c4a"},
	}
}

// SeveritySlices counts failed and errored findings by severity.
func SeveritySlices(r *types.Report) []ChartSlice {
	counts := map[types.Severity]int{}
	for _, f := range r.Findings {
		if f.Status != types.StatusFail && f.Status != types.StatusError {
			continue
		}
		counts[f.Severity]++
	}
	order := []types.Severity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
		types.SeverityInfo,
	}
	colors := map[types.Severity]string{
		types.SeverityCritical: "#7a1020",
		types.SeverityHigh:     "#c0392b",
		types.SeverityMedium:   "#c47f17",
		types.SeverityLow:      "#3d6e9c",
		types.SeverityInfo:     "#5a6b7d",
	}
	out := make([]ChartSlice, 0, len(order))
	for _, sev := range order {
		if counts[sev] == 0 {
			continue
		}
		label := string(sev)
		if label != "" {
			label = strings.ToUpper(label[:1]) + label[1:]
		}
		out = append(out, ChartSlice{
			Label: label,
			Count: counts[sev],
			Color: colors[sev],
		})
	}
	return out
}

// CategorySlices counts all findings by category.
func CategorySlices(r *types.Report) []ChartSlice {
	counts := map[string]int{}
	for _, f := range r.Findings {
		key := string(f.Category)
		if key == "" {
			key = "other"
		}
		counts[key]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	palette := []string{"#0d7a55", "#1f5f8a", "#8a5a12", "#6b3d7a", "#3d6e5a"}
	out := make([]ChartSlice, 0, len(keys))
	for i, k := range keys {
		out = append(out, ChartSlice{
			Label: k,
			Count: counts[k],
			Color: palette[i%len(palette)],
		})
	}
	return out
}

// PriorityFindings returns fail/error/warn findings sorted by severity weight.
func PriorityFindings(r *types.Report) []types.Finding {
	out := make([]types.Finding, 0)
	for _, f := range r.Findings {
		if f.Status == types.StatusFail || f.Status == types.StatusError || f.Status == types.StatusWarn {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		wi, wj := severityWeight(out[i].Severity), severityWeight(out[j].Severity)
		if wi != wj {
			return wi > wj
		}
		return out[i].Title < out[j].Title
	})
	return out
}

func severityWeight(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 5
	case types.SeverityHigh:
		return 4
	case types.SeverityMedium:
		return 3
	case types.SeverityLow:
		return 2
	default:
		return 1
	}
}
