package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Romstar/auth-chaser/pkg/types"
)

// Supported output formats.
const (
	FormatText  = "text"
	FormatJSON  = "json"
	FormatSARIF = "sarif"
	FormatHTML  = "html"
	FormatPDF   = "pdf"
	FormatCSV   = "csv"
)

// NormalizeFormat lowercases and validates a format name.
func NormalizeFormat(format string) (string, error) {
	f := strings.ToLower(strings.TrimSpace(format))
	if f == "" {
		f = FormatText
	}
	switch f {
	case FormatText, FormatJSON, FormatSARIF, FormatHTML, FormatPDF, FormatCSV:
		return f, nil
	default:
		return "", fmt.Errorf("unsupported report format %q (use text|json|sarif|html|pdf|csv)", format)
	}
}

// ContentType returns the MIME type for a format.
func ContentType(format string) string {
	switch format {
	case FormatJSON:
		return "application/json"
	case FormatSARIF:
		return "application/sarif+json"
	case FormatHTML:
		return "text/html; charset=utf-8"
	case FormatPDF:
		return "application/pdf"
	case FormatCSV:
		return "text/csv; charset=utf-8"
	default:
		return "text/plain; charset=utf-8"
	}
}

// FileExtension returns the usual file extension for a format.
func FileExtension(format string) string {
	switch format {
	case FormatJSON:
		return ".json"
	case FormatSARIF:
		return ".sarif"
	case FormatHTML:
		return ".html"
	case FormatPDF:
		return ".pdf"
	case FormatCSV:
		return ".csv"
	default:
		return ".txt"
	}
}

// Write writes the report in the requested format to w.
func Write(w io.Writer, format string, r *types.Report) error {
	f, err := NormalizeFormat(format)
	if err != nil {
		return err
	}
	switch f {
	case FormatJSON:
		return WriteJSON(w, r)
	case FormatSARIF:
		return WriteSARIF(w, r)
	case FormatHTML:
		return WriteHTML(w, r)
	case FormatPDF:
		return WritePDF(w, r)
	case FormatCSV:
		return WriteCSV(w, r)
	default:
		return WriteText(w, r)
	}
}

// WriteToPath writes the report to a file path (created/truncated).
func WriteToPath(path, format string, r *types.Report) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create report file: %w", err)
	}
	defer f.Close()
	if err := Write(f, format, r); err != nil {
		return err
	}
	return f.Close()
}
