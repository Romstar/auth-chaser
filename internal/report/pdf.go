package report

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Romstar/auth-chaser/pkg/types"
	"github.com/phpdave11/gofpdf"
)

// WritePDF writes a designed multi-page PDF assessment report with charts.
func WritePDF(w io.Writer, r *types.Report) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetTitle("auth-chaser report — "+r.Target, false)
	pdf.SetAuthor("auth-chaser "+r.ToolVersion, false)
	pdf.SetCreator("auth-chaser", false)
	pdf.SetMargins(16, 18, 16)
	pdf.SetAutoPageBreak(true, 18)

	brand, err := RenderBrandMarkPNG(160)
	if err != nil {
		return err
	}
	donut, err := RenderDonutPNG(StatusSlices(r), 320)
	if err != nil {
		return err
	}
	sev := SeveritySlices(r)
	if len(sev) == 0 {
		sev = []ChartSlice{{Label: "None", Count: 1, Color: "#1f8a5b"}}
	}
	bars, err := RenderBarsPNG(sev, 640, 240)
	if err != nil {
		return err
	}

	pdf.RegisterImageOptionsReader("brand", gofpdf.ImageOptions{ImageType: "PNG"}, bytes.NewReader(brand))
	pdf.RegisterImageOptionsReader("donut", gofpdf.ImageOptions{ImageType: "PNG"}, bytes.NewReader(donut))
	pdf.RegisterImageOptionsReader("bars", gofpdf.ImageOptions{ImageType: "PNG"}, bytes.NewReader(bars))

	narr := BuildNarrative(r)
	pdf.AddPage()
	drawPDFHero(pdf, r, narr)
	drawPDFSummary(pdf, r, narr)
	drawPDFCharts(pdf, r)
	drawPDFFindings(pdf, PriorityFindings(r), "Priority findings")
	drawPDFFindings(pdf, r.Findings, "Full finding log")
	drawPDFFooterNote(pdf, r)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return err
	}
	_, err = w.Write(buf.Bytes())
	return err
}

func drawPDFHero(pdf *gofpdf.Fpdf, r *types.Report, narr Narrative) {
	pdf.SetFillColor(11, 61, 46)
	pdf.Rect(0, 0, 210, 52, "F")
	pdf.ImageOptions("brand", 14, 10, 18, 18, false, gofpdf.ImageOptions{ImageType: "PNG"}, 0, "")

	pdf.SetTextColor(244, 250, 247)
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetXY(36, 11)
	pdf.Cell(140, 5, "AUTH-CHASER  ·  DEFENSIVE VERIFICATION REPORT")

	pdf.SetFont("Helvetica", "B", 16)
	pdf.SetXY(36, 18)
	pdf.MultiCell(158, 7, narr.Headline, "", "", false)

	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(215, 235, 225)
	pdf.SetXY(36, 34)
	pdf.MultiCell(158, 4.5, trunc(r.Target, 90), "", "", false)

	pdf.SetY(58)
	pdf.SetTextColor(26, 36, 46)
	pdf.SetFont("Helvetica", "", 9)
	row := [][2]string{
		{"Duration", formatDuration(r.DurationMS)},
		{"Pass rate", passRate(r)},
		{"Authorized", fmt.Sprintf("%v", r.Authorized)},
		{"Version", r.ToolVersion},
	}
	x := 16.0
	for _, cell := range row {
		pdf.SetXY(x, 58)
		pdf.SetFillColor(255, 253, 249)
		pdf.SetDrawColor(217, 210, 198)
		pdf.Rect(x, 58, 42, 14, "FD")
		pdf.SetFont("Helvetica", "", 7)
		pdf.SetTextColor(91, 107, 122)
		pdf.SetXY(x+2, 59.5)
		pdf.Cell(38, 4, strings.ToUpper(cell[0]))
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(26, 36, 46)
		pdf.SetXY(x+2, 64.5)
		pdf.Cell(38, 5, trunc(cell[1], 22))
		x += 45
	}
	pdf.SetY(78)
}

func drawPDFSummary(pdf *gofpdf.Fpdf, r *types.Report, narr Narrative) {
	pdf.SetFont("Helvetica", "B", 13)
	pdf.SetTextColor(13, 92, 66)
	pdf.Cell(0, 7, "Executive summary")
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(26, 36, 46)
	pdf.MultiCell(0, 5, narr.Body, "", "", false)
	pdf.Ln(2)
	pdf.SetFillColor(228, 243, 236)
	pdf.SetDrawColor(13, 92, 66)
	y := pdf.GetY()
	pdf.Rect(16, y, 178, 12, "F")
	pdf.SetXY(18, y+3)
	pdf.SetFont("Helvetica", "B", 9)
	pdf.MultiCell(174, 4.5, narr.Risk, "", "", false)
	pdf.Ln(4)
	if len(r.Packs) > 0 {
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(91, 107, 122)
		pdf.Cell(0, 4, "Packs: "+strings.Join(r.Packs, ", "))
		pdf.Ln(5)
	}
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(91, 107, 122)
	pdf.Cell(0, 4, fmt.Sprintf("Started %s", r.StartedAt.Format(time.RFC3339)))
	pdf.Ln(8)
}

func drawPDFCharts(pdf *gofpdf.Fpdf, r *types.Report) {
	ensureSpace(pdf, 70)
	pdf.SetFont("Helvetica", "B", 13)
	pdf.SetTextColor(13, 92, 66)
	pdf.Cell(0, 7, "Outcome at a glance")
	pdf.Ln(8)

	pdf.ImageOptions("donut", 18, pdf.GetY(), 52, 52, false, gofpdf.ImageOptions{ImageType: "PNG"}, 0, "")
	pdf.ImageOptions("bars", 78, pdf.GetY()+4, 110, 42, false, gofpdf.ImageOptions{ImageType: "PNG"}, 0, "")
	pdf.SetY(pdf.GetY() + 56)

	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(91, 107, 122)
	x := 16.0
	for _, s := range StatusSlices(r) {
		if s.Count == 0 {
			continue
		}
		pdf.SetXY(x, pdf.GetY())
		pdf.Cell(35, 4, fmt.Sprintf("%s %d", s.Label, s.Count))
		x += 36
	}
	pdf.Ln(8)

	stats := [][2]string{
		{"Pass", fmt.Sprintf("%d", r.PassCount)},
		{"Fail", fmt.Sprintf("%d", r.FailCount)},
		{"Warn", fmt.Sprintf("%d", r.WarnCount)},
		{"Skip", fmt.Sprintf("%d", r.SkipCount)},
		{"Error", fmt.Sprintf("%d", r.ErrorCount)},
	}
	x = 16
	for _, st := range stats {
		pdf.SetDrawColor(217, 210, 198)
		pdf.SetFillColor(255, 255, 255)
		pdf.Rect(x, pdf.GetY(), 34, 12, "FD")
		pdf.SetXY(x+2, pdf.GetY()+1.5)
		pdf.SetFont("Helvetica", "B", 11)
		pdf.SetTextColor(26, 36, 46)
		pdf.Cell(30, 5, st[1])
		pdf.SetXY(x+2, pdf.GetY()+5.5)
		pdf.SetFont("Helvetica", "", 7)
		pdf.SetTextColor(91, 107, 122)
		pdf.Cell(30, 4, strings.ToUpper(st[0]))
		x += 36
	}
	pdf.Ln(16)
}

func drawPDFFindings(pdf *gofpdf.Fpdf, findings []types.Finding, title string) {
	if len(findings) == 0 {
		return
	}
	ensureSpace(pdf, 30)
	pdf.SetFont("Helvetica", "B", 13)
	pdf.SetTextColor(13, 92, 66)
	pdf.Cell(0, 7, title)
	pdf.Ln(8)

	for _, f := range findings {
		ensureSpace(pdf, 28)
		pdf.SetFont("Helvetica", "B", 8)
		statusRGB := statusColor(f.Status)
		pdf.SetFillColor(statusRGB[0], statusRGB[1], statusRGB[2])
		pdf.SetTextColor(255, 255, 255)
		pdf.CellFormat(16, 5, strings.ToUpper(string(f.Status)), "0", 0, "C", true, 0, "")
		sevRGB := severityColor(f.Severity)
		pdf.SetFillColor(sevRGB[0], sevRGB[1], sevRGB[2])
		pdf.CellFormat(20, 5, strings.ToUpper(string(f.Severity)), "0", 0, "C", true, 0, "")
		pdf.SetTextColor(26, 36, 46)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.Cell(0, 5, "  "+trunc(f.Title, 70))
		pdf.Ln(6)

		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(70, 82, 94)
		pdf.MultiCell(0, 4.5, f.Summary, "", "", false)
		if f.Evidence != "" {
			pdf.SetFont("Courier", "", 8)
			pdf.SetTextColor(90, 70, 50)
			pdf.MultiCell(0, 4, "Evidence: "+trunc(f.Evidence, 400), "", "", false)
		}
		if f.Remediation != "" {
			pdf.SetFont("Helvetica", "", 9)
			pdf.SetTextColor(13, 92, 66)
			pdf.MultiCell(0, 4.5, "Fix: "+f.Remediation, "", "", false)
		}
		pdf.SetFont("Helvetica", "", 7)
		pdf.SetTextColor(120, 130, 140)
		meta := f.CheckID
		if f.Pack != "" {
			meta += " · pack " + f.Pack
		}
		if f.CWE != "" {
			meta += " · " + f.CWE
		}
		pdf.Cell(0, 4, meta)
		pdf.Ln(7)
	}
}

func drawPDFFooterNote(pdf *gofpdf.Fpdf, r *types.Report) {
	ensureSpace(pdf, 16)
	pdf.SetDrawColor(217, 210, 198)
	pdf.Line(16, pdf.GetY(), 194, pdf.GetY())
	pdf.Ln(4)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(91, 107, 122)
	pdf.MultiCell(0, 4, fmt.Sprintf(
		"Generated by auth-chaser %s at %s. Defensive verification only — unauthorized scanning is prohibited.",
		r.ToolVersion,
		time.Now().UTC().Format(time.RFC3339),
	), "", "", false)
}

func ensureSpace(pdf *gofpdf.Fpdf, need float64) {
	_, _, _, bottom := pdf.GetMargins()
	pageH, _ := pdf.GetPageSize()
	if pdf.GetY()+need > pageH-bottom {
		pdf.AddPage()
	}
}

func passRate(r *types.Report) string {
	total := len(r.Findings)
	if total == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.0f%%", 100*float64(r.PassCount)/float64(total))
}

func trunc(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func statusColor(s types.Status) [3]int {
	switch s {
	case types.StatusPass:
		return [3]int{31, 138, 91}
	case types.StatusFail:
		return [3]int{192, 57, 43}
	case types.StatusWarn:
		return [3]int{196, 127, 23}
	case types.StatusError:
		return [3]int{142, 44, 74}
	default:
		return [3]int{107, 124, 143}
	}
}

func severityColor(s types.Severity) [3]int {
	switch s {
	case types.SeverityCritical:
		return [3]int{122, 16, 32}
	case types.SeverityHigh:
		return [3]int{192, 57, 43}
	case types.SeverityMedium:
		return [3]int{196, 127, 23}
	case types.SeverityLow:
		return [3]int{61, 110, 156}
	default:
		return [3]int{90, 107, 125}
	}
}
