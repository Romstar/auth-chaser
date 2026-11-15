package report

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/Romstar/auth-chaser/pkg/types"
)

type htmlView struct {
	Report        *types.Report
	Narrative     Narrative
	BrandDataURI  template.URL
	DonutDataURI  template.URL
	BarsDataURI   template.URL
	StatusLegend  []ChartSlice
	SeverityBars  []ChartSlice
	CategoryBars  []ChartSlice
	Priority      []types.Finding
	AllFindings   []types.Finding
	GeneratedAt   string
	DurationLabel string
	PacksLabel    string
	PassRate      string
}

// WriteHTML writes a self-contained, designed HTML assessment report.
func WriteHTML(w io.Writer, r *types.Report) error {
	view, err := buildHTMLView(r)
	if err != nil {
		return err
	}
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"upper": strings.ToUpper,
		"sevClass": func(s types.Severity) string {
			return "sev-" + string(s)
		},
		"statusClass": func(s types.Status) string {
			return "st-" + string(s)
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, view)
}

func buildHTMLView(r *types.Report) (htmlView, error) {
	brand, err := RenderBrandMarkPNG(128)
	if err != nil {
		return htmlView{}, err
	}
	donut, err := RenderDonutPNG(StatusSlices(r), 280)
	if err != nil {
		return htmlView{}, err
	}
	sev := SeveritySlices(r)
	if len(sev) == 0 {
		sev = []ChartSlice{{Label: "None", Count: 1, Color: "#1f8a5b"}}
	}
	bars, err := RenderBarsPNG(sev, 520, 200)
	if err != nil {
		return htmlView{}, err
	}

	total := len(r.Findings)
	passRate := "n/a"
	if total > 0 {
		passRate = fmt.Sprintf("%.0f%%", 100*float64(r.PassCount)/float64(total))
	}

	return htmlView{
		Report:        r,
		Narrative:     BuildNarrative(r),
		BrandDataURI:  template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(brand)),
		DonutDataURI:  template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(donut)),
		BarsDataURI:   template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(bars)),
		StatusLegend:  StatusSlices(r),
		SeverityBars:  SeveritySlices(r),
		CategoryBars:  CategorySlices(r),
		Priority:      PriorityFindings(r),
		AllFindings:   r.Findings,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		DurationLabel: formatDuration(r.DurationMS),
		PacksLabel:    strings.Join(r.Packs, ", "),
		PassRate:      passRate,
	}, nil
}

// HTMLBytes returns the HTML report as bytes (for PDF reuse or tests).
func HTMLBytes(r *types.Report) ([]byte, error) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>auth-chaser report — {{.Report.Target}}</title>
<style>
  :root {
    --ink: #1a242e;
    --muted: #5b6b7a;
    --paper: #f7f4ef;
    --panel: #fffdf9;
    --line: #d9d2c6;
    --brand: #0d5c42;
    --brand-soft: #e4f3ec;
    --accent: #1f8a5b;
    --fail: #c0392b;
    --warn: #c47f17;
    --skip: #6b7c8f;
    --err: #8e2c4a;
    --display: "Fraunces", "Iowan Old Style", "Palatino Linotype", Palatino, serif;
    --sans: "DM Sans", "Avenir Next", "Segoe UI", sans-serif;
    --mono: "IBM Plex Mono", "SFMono-Regular", ui-monospace, monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    color: var(--ink);
    font-family: var(--sans);
    background:
      radial-gradient(900px 420px at 0% 0%, #dceee4 0%, transparent 55%),
      radial-gradient(700px 360px at 100% 8%, #efe6d6 0%, transparent 50%),
      linear-gradient(180deg, #ebe4d8 0%, var(--paper) 28%, var(--paper) 100%);
    line-height: 1.55;
  }
  .wrap { max-width: 980px; margin: 0 auto; padding: 2.5rem 1.25rem 4rem; }
  .hero {
    position: relative;
    overflow: hidden;
    border: 1px solid var(--line);
    border-radius: 18px;
    background:
      linear-gradient(135deg, #0b3d2e 0%, #0d5c42 48%, #1a6f55 100%);
    color: #f4faf7;
    padding: 2rem 2rem 1.75rem;
    box-shadow: 0 18px 40px rgba(13, 61, 46, 0.18);
  }
  .hero-top { display: flex; gap: 1.25rem; align-items: center; }
  .hero img.brand { width: 72px; height: 72px; flex: none; }
  .eyebrow {
    font-family: var(--mono);
    font-size: 0.78rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    opacity: 0.85;
    margin: 0 0 0.35rem;
  }
  .hero h1 {
    font-family: var(--display);
    font-weight: 600;
    font-size: clamp(1.8rem, 4vw, 2.6rem);
    letter-spacing: -0.02em;
    margin: 0;
    line-height: 1.15;
  }
  .hero .sub {
    margin: 0.65rem 0 0;
    max-width: 40rem;
    color: #d7ebe1;
    font-size: 1.02rem;
  }
  .meta {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 0.75rem;
    margin-top: 1.5rem;
  }
  .meta div {
    background: rgba(255,255,255,0.08);
    border: 1px solid rgba(255,255,255,0.14);
    border-radius: 12px;
    padding: 0.75rem 0.9rem;
  }
  .meta .k { display:block; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.06em; opacity: 0.75; }
  .meta .v { display:block; margin-top: 0.2rem; font-family: var(--mono); font-size: 0.92rem; word-break: break-all; }
  section {
    margin-top: 1.75rem;
    background: color-mix(in srgb, var(--panel) 94%, transparent);
    border: 1px solid var(--line);
    border-radius: 16px;
    padding: 1.4rem 1.5rem 1.55rem;
  }
  section h2 {
    font-family: var(--display);
    font-size: 1.45rem;
    margin: 0 0 0.55rem;
    letter-spacing: -0.01em;
  }
  section p.lead { margin: 0 0 0.85rem; color: var(--muted); max-width: 48rem; }
  .risk {
    margin: 0.85rem 0 0;
    padding: 0.85rem 1rem;
    border-radius: 10px;
    background: var(--brand-soft);
    border-left: 4px solid var(--brand);
    color: #143528;
    font-weight: 550;
  }
  .charts {
    display: grid;
    grid-template-columns: 280px 1fr;
    gap: 1.25rem;
    align-items: center;
  }
  .chart-card {
    text-align: center;
  }
  .chart-card img, .bars img {
    max-width: 100%;
    height: auto;
    border-radius: 12px;
    border: 1px solid var(--line);
  }
  .legend {
    display: flex; flex-wrap: wrap; gap: 0.55rem 1rem;
    justify-content: center; margin-top: 0.75rem;
    font-size: 0.85rem; color: var(--muted);
  }
  .legend span::before {
    content: "";
    display: inline-block;
    width: 0.65rem; height: 0.65rem;
    border-radius: 999px;
    margin-right: 0.35rem;
    background: var(--swatch, #888);
    vertical-align: middle;
  }
  .stats {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    gap: 0.65rem;
    margin-top: 1rem;
  }
  .stat {
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 0.85rem 0.75rem;
    text-align: center;
    background: #fff;
  }
  .stat strong { display: block; font-size: 1.45rem; font-family: var(--display); }
  .stat span { color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .finding {
    border-top: 1px solid var(--line);
    padding: 1rem 0 0.85rem;
  }
  .finding:first-of-type { border-top: 0; padding-top: 0.25rem; }
  .finding-head {
    display: flex; flex-wrap: wrap; gap: 0.45rem 0.65rem; align-items: baseline;
  }
  .finding h3 {
    margin: 0;
    font-size: 1.05rem;
    font-weight: 650;
    flex: 1 1 auto;
  }
  .badge {
    font-family: var(--mono);
    font-size: 0.72rem;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    padding: 0.22rem 0.5rem;
    border-radius: 999px;
    border: 1px solid var(--line);
    background: #fff;
  }
  .st-pass { color: #0d5c42; background: #e4f3ec; border-color: #b7dcc9; }
  .st-fail { color: #7a1c14; background: #f8e6e4; border-color: #e6b8b2; }
  .st-warn { color: #7a5208; background: #f8efd9; border-color: #e6d4a4; }
  .st-skip { color: #44505c; background: #eef1f4; border-color: #cfd6de; }
  .st-error { color: #6a1834; background: #f6e4ea; border-color: #e0b4c2; }
  .sev-critical { color: #fff; background: #7a1020; border-color: #7a1020; }
  .sev-high { color: #fff; background: #c0392b; border-color: #c0392b; }
  .sev-medium { color: #fff; background: #c47f17; border-color: #c47f17; }
  .sev-low { color: #fff; background: #3d6e9c; border-color: #3d6e9c; }
  .sev-info { color: #fff; background: #5a6b7d; border-color: #5a6b7d; }
  .finding p { margin: 0.45rem 0 0; color: var(--muted); }
  .finding .evidence, .finding .fix {
    margin-top: 0.55rem;
    padding: 0.65rem 0.8rem;
    border-radius: 8px;
    font-size: 0.92rem;
  }
  .finding .evidence {
    background: #f1ece4;
    font-family: var(--mono);
    white-space: pre-wrap;
    word-break: break-word;
  }
  .finding .fix {
    background: var(--brand-soft);
    border-left: 3px solid var(--brand);
    color: #143528;
  }
  .meta-row {
    margin-top: 0.45rem;
    font-family: var(--mono);
    font-size: 0.78rem;
    color: var(--muted);
  }
  footer {
    margin-top: 2rem;
    color: var(--muted);
    font-size: 0.85rem;
    text-align: center;
  }
  @media (max-width: 800px) {
    .meta, .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .charts { grid-template-columns: 1fr; }
  }
  @media print {
    body { background: white; }
    .hero { box-shadow: none; break-inside: avoid; }
    section { break-inside: avoid; }
  }
</style>
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;550;650&family=Fraunces:opsz,wght@9..144,500;9..144,600&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet" />
</head>
<body>
  <div class="wrap">
    <header class="hero">
      <div class="hero-top">
        <img class="brand" src="{{.BrandDataURI}}" alt="auth-chaser mark" />
        <div>
          <p class="eyebrow">auth-chaser · defensive verification report</p>
          <h1>{{.Narrative.Headline}}</h1>
          <p class="sub">{{.Narrative.Body}}</p>
        </div>
      </div>
      <div class="meta">
        <div><span class="k">Target</span><span class="v">{{.Report.Target}}</span></div>
        <div><span class="k">Duration</span><span class="v">{{.DurationLabel}}</span></div>
        <div><span class="k">Pass rate</span><span class="v">{{.PassRate}}</span></div>
        <div><span class="k">Version</span><span class="v">{{.Report.ToolVersion}}</span></div>
      </div>
    </header>

    <section>
      <h2>Executive summary</h2>
      <p class="lead">{{.Narrative.Body}}</p>
      <p class="risk">{{.Narrative.Risk}}</p>
      {{if .PacksLabel}}<p class="meta-row">Packs: {{.PacksLabel}}</p>{{end}}
      <p class="meta-row">Started {{.Report.StartedAt.Format "2006-01-02 15:04:05 MST"}} · Authorized {{.Report.Authorized}}</p>
    </section>

    <section>
      <h2>Outcome at a glance</h2>
      <div class="charts">
        <div class="chart-card">
          <img src="{{.DonutDataURI}}" alt="Status distribution chart" width="280" height="280" />
          <div class="legend">
            {{range .StatusLegend}}
              {{if gt .Count 0}}<span style="--swatch:{{.Color}}">{{.Label}} {{.Count}}</span>{{end}}
            {{end}}
          </div>
        </div>
        <div class="bars">
          <p class="lead">Failed and errored findings by severity</p>
          <img src="{{.BarsDataURI}}" alt="Severity bar chart" width="520" height="200" />
        </div>
      </div>
      <div class="stats">
        <div class="stat"><strong>{{.Report.PassCount}}</strong><span>Pass</span></div>
        <div class="stat"><strong>{{.Report.FailCount}}</strong><span>Fail</span></div>
        <div class="stat"><strong>{{.Report.WarnCount}}</strong><span>Warn</span></div>
        <div class="stat"><strong>{{.Report.SkipCount}}</strong><span>Skip</span></div>
        <div class="stat"><strong>{{.Report.ErrorCount}}</strong><span>Error</span></div>
      </div>
    </section>

    {{if .Priority}}
    <section>
      <h2>Priority findings</h2>
      <p class="lead">Failures, errors, and warnings ordered by severity.</p>
      {{range .Priority}}
      <article class="finding">
        <div class="finding-head">
          <span class="badge {{statusClass .Status}}">{{upper (printf "%s" .Status)}}</span>
          <span class="badge {{sevClass .Severity}}">{{upper (printf "%s" .Severity)}}</span>
          <h3>{{.Title}}</h3>
        </div>
        <p>{{.Summary}}</p>
        {{if .Evidence}}<div class="evidence">{{.Evidence}}</div>{{end}}
        {{if .Remediation}}<div class="fix"><strong>Fix:</strong> {{.Remediation}}</div>{{end}}
        <div class="meta-row">
          {{.CheckID}}
          {{if .Pack}} · pack {{.Pack}}{{end}}
          {{if .CWE}} · {{.CWE}}{{end}}
          {{if .Category}} · {{.Category}}{{end}}
        </div>
      </article>
      {{end}}
    </section>
    {{end}}

    <section>
      <h2>Full finding log</h2>
      <p class="lead">Every check from this chase, including passes and skips.</p>
      {{range .AllFindings}}
      <article class="finding">
        <div class="finding-head">
          <span class="badge {{statusClass .Status}}">{{upper (printf "%s" .Status)}}</span>
          <span class="badge {{sevClass .Severity}}">{{upper (printf "%s" .Severity)}}</span>
          <h3>{{.Title}}</h3>
        </div>
        <p>{{.Summary}}</p>
        {{if .Evidence}}<div class="evidence">{{.Evidence}}</div>{{end}}
        {{if .Remediation}}<div class="fix"><strong>Fix:</strong> {{.Remediation}}</div>{{end}}
        <div class="meta-row">
          {{.CheckID}}
          {{if .Pack}} · pack {{.Pack}}{{end}}
          {{if .CWE}} · {{.CWE}}{{end}}
        </div>
      </article>
      {{else}}
      <p class="lead">No findings recorded.</p>
      {{end}}
    </section>

    <footer>
      Generated by auth-chaser {{.Report.ToolVersion}} at {{.GeneratedAt}}.
      Defensive verification only — unauthorized scanning is prohibited.
    </footer>
  </div>
</body>
</html>
`
