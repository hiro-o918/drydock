package exporter

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/hiro-o918/drydock"
)

// TableExporter exports analysis results in a delimiter-separated format (CSV/TSV).
type TableExporter struct {
	writer *csv.Writer
}

// NewCSVExporter creates a new exporter that writes Comma-Separated Values.
func NewCSVExporter(w io.Writer) *TableExporter {
	return newTableExporter(w, ',')
}

// NewTSVExporter creates a new exporter that writes Tab-Separated Values.
func NewTSVExporter(w io.Writer) *TableExporter {
	return newTableExporter(w, '\t')
}

// newTableExporter is the internal factory that configures the csv.Writer.
func newTableExporter(w io.Writer, comma rune) *TableExporter {
	cw := csv.NewWriter(w)
	cw.Comma = comma // Here is where we switch between CSV and TSV
	return &TableExporter{
		writer: cw,
	}
}

// NewDefaultCSVExporter creates a CSV exporter to stdout.
func NewDefaultCSVExporter() *TableExporter {
	return NewCSVExporter(os.Stdout)
}

// Export outputs the analysis results.
func (e *TableExporter) Export(ctx context.Context, results []drydock.AnalyzeResult) error {
	// 1. Write Header
	header := []string{
		"Scan Time",
		"Image URI",
		"Vulnerability ID",
		"Severity",
		"CVSS Score",
		"Package Name",
		"Installed Version",
		"Fixed Version",
		"Description",
		"Reference URL",
	}

	if err := e.writer.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// 2. Write Data Rows
	for _, result := range results {
		// Pre-calculate shared fields for this artifact
		imageURI := result.Artifact.String()
		scanTime := result.ScanTime.Format(time.RFC3339)

		for _, v := range result.Vulnerabilities {
			// Use the shared logic to build the row
			record := buildRecord(scanTime, imageURI, v)

			if err := e.writer.Write(record); err != nil {
				return fmt.Errorf("failed to write record for %s: %w", v.ID, err)
			}
		}
	}

	e.writer.Flush()
	if err := e.writer.Error(); err != nil {
		return fmt.Errorf("flush error: %w", err)
	}

	return nil
}

// buildRecord centralizes the logic of converting a single vulnerability into a row of strings.
// This ensures CSV and TSV always output the same data structure.
func buildRecord(scanTime, imageURI string, v drydock.Vulnerability) []string {
	// Handle URL logic (pick first or empty)
	urlStr := ""
	if len(v.URLs) > 0 {
		urlStr = v.URLs[0]
	}

	// Clean description (optional: limit length or remove excessive newlines if needed)
	// For standard CSV/TSV, the writer handles newlines automatically via quoting.
	desc := strings.TrimSpace(v.Description)

	return []string{
		scanTime,
		imageURI,
		v.ID,
		string(v.Severity),
		fmt.Sprintf("%.1f", v.CVSSScore),
		v.PackageName,
		v.InstalledVersion,
		v.FixedVersion,
		desc,
		urlStr,
	}
}
