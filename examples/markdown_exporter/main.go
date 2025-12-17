package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"text/template"

	"github.com/rs/zerolog/log"

	"github.com/hiro-o918/drydock"
	"github.com/hiro-o918/drydock/schemas"
)

// MarkdownExporter exports vulnerability results in Markdown format
type MarkdownExporter struct {
	writer io.Writer
}

// NewMarkdownExporter creates a new Markdown exporter with the given writer
func NewMarkdownExporter(writer io.Writer) *MarkdownExporter {
	return &MarkdownExporter{
		writer: writer,
	}
}

// Export formats and outputs the analysis results in Markdown format
func (e *MarkdownExporter) Export(ctx context.Context, results []schemas.AnalyzeResult) error {
	// Define a template for the markdown output
	const markdownTemplate = `# Vulnerability Scan Report

{{ range $resultIndex, $result := . }}
## Image: {{ $result.Artifact.String }}

**Scan Time**: {{ $result.ScanTime.Format "2006-01-02 15:04:05" }}

### Summary

Total vulnerabilities found: {{ $result.Summary.TotalCount }}
Vulnerabilities with fixes available: {{ $result.Summary.FixableCount }}

#### Severity Breakdown

| Severity Level | Count |
|---------------|-------|
{{ range $severity, $count := $result.Summary.CountBySeverity }}| {{ $severity }} | {{ $count }} |
{{ end }}

### Vulnerabilities

| ID | Severity | Package | Installed Version | Fixed Version | CVSS Score |
|----|----------|---------|-------------------|---------------|------------|
{{ range $vulnIndex, $vuln := $result.Vulnerabilities }}| {{ $vuln.ID }} | {{ $vuln.Severity }} | {{ $vuln.PackageName }} | {{ $vuln.InstalledVersion }} | {{ $vuln.FixedVersion }} | {{ $vuln.CVSSScore }} |
{{ end }}
{{ end }}
`

	// Parse the template
	tmpl, err := template.New("markdown").Parse(markdownTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse markdown template: %w", err)
	}

	// Execute the template with the results
	err = tmpl.Execute(e.writer, results)
	if err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}

func main() {
	var (
		location    string
		projectID   string
		minSeverity string
		fixableOnly bool
	)

	flag.StringVar(&location, "location", "", "Artifact Registry location (required)")
	flag.StringVar(&location, "l", "", "Artifact Registry location (shorthand)")
	flag.StringVar(&projectID, "project", "", "Google Cloud Project ID")
	flag.StringVar(&projectID, "p", "", "Google Cloud Project ID (shorthand)")
	flag.StringVar(&minSeverity, "min-severity", "HIGH", "Minimum vulnerability severity (LOW, MEDIUM, HIGH, CRITICAL)")
	flag.BoolVar(&fixableOnly, "fixable", false, "Only show vulnerabilities that have a fix available")

	flag.Parse()

	if location == "" {
		fmt.Fprintf(os.Stderr, "Error: location is required\n")
		flag.Usage()
		os.Exit(1)
	}

	ctx := context.Background()

	// Setup scanner with options
	scannerOpts := []drydock.ScannerOption{}

	if projectID != "" {
		scannerOpts = append(scannerOpts, drydock.WithProjectID(projectID))
	}

	// Set a custom exporter that uses our MarkdownExporter
	markdownExporter := NewMarkdownExporter(os.Stdout)
	scannerOpts = append(scannerOpts, drydock.WithExporter(markdownExporter))

	// Initialize scanner
	scanner, err := drydock.NewScanner(ctx, location, scannerOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing scanner: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close scanner resources")
		}
	}()

	// Parse severity level
	severity := schemas.SeverityHigh
	switch minSeverity {
	case "LOW":
		severity = schemas.SeverityLow
	case "MEDIUM":
		severity = schemas.SeverityMedium
	case "HIGH":
		severity = schemas.SeverityHigh
	case "CRITICAL":
		severity = schemas.SeverityCritical
	default:
		fmt.Fprintf(os.Stderr, "Invalid severity level: %s. Using HIGH.\n", minSeverity)
	}

	// Run scan
	fmt.Fprintf(os.Stderr, "Starting vulnerability scan...\n")
	if err := scanner.Scan(ctx, severity, fixableOnly); err != nil {
		fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Scan completed successfully.\n")
}
