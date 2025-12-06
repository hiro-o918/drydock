package main

import (
	"context"
	"io"
	"time"
)

// ============================================================================
// Core Domain Types
// ============================================================================

// Severity represents the severity level
type Severity string

const (
	SeverityUnspecified Severity = "UNSPECIFIED"
	SeverityMinimal     Severity = "MINIMAL"
	SeverityLow         Severity = "LOW"
	SeverityMedium      Severity = "MEDIUM"
	SeverityHigh        Severity = "HIGH"
	SeverityCritical    Severity = "CRITICAL"
)

// Vulnerability represents a single vulnerability finding
type Vulnerability struct {
	// ID is the CVE identifier
	ID string

	// Severity is the vulnerability severity level
	Severity Severity

	// PackageName is the affected package
	PackageName string

	// InstalledVersion is the currently installed version
	InstalledVersion string

	// FixedVersion is the version that fixes the vulnerability (if available)
	FixedVersion string

	// Description provides details about the vulnerability
	Description string

	// CVSSScore is the CVSS score
	CVSSScore float64

	// URLs contains reference links
	URLs []string
}

// VulnerabilitySummary provides aggregated statistics
type VulnerabilitySummary struct {
	// TotalCount is the total number of vulnerabilities
	TotalCount int

	// CountBySeverity maps severity levels to counts
	CountBySeverity map[Severity]int

	// FixableCount is the number of vulnerabilities with fixes available
	FixableCount int
}

// ============================================================================
// Analyzer Component
// ============================================================================

// Analyzer fetches and processes vulnerability data
type Analyzer interface {
	// Analyze retrieves vulnerabilities for the specified image
	Analyze(ctx context.Context, req AnalyzeRequest) (*AnalyzeResult, error)
}

// AnalyzeRequest contains parameters for vulnerability analysis
type AnalyzeRequest struct {
	// ProjectID is the GCP project ID
	ProjectID string

	// Location is the Artifact Registry location (e.g., us-central1)
	Location string

	// Repository is the repository name
	Repository string

	// Image is the image name
	Image string

	// Tag is the image tag
	Tag string

	// MinSeverity filters vulnerabilities by minimum severity
	MinSeverity Severity
}

// AnalyzeResult contains the analysis results
type AnalyzeResult struct {
	// ImageRef is the full image reference
	ImageRef string

	// ScanTime is when the scan was performed
	ScanTime time.Time

	// Vulnerabilities is the list of found vulnerabilities
	Vulnerabilities []Vulnerability

	// Summary provides aggregated statistics
	Summary VulnerabilitySummary
}

// ============================================================================
// Exporter Component
// ============================================================================

// Exporter defines the interface for exporting analysis results
type Exporter interface {
	// Export outputs the analysis results to the configured destination
	Export(ctx context.Context, result *AnalyzeResult) error
}

// JSONExporter exports results as JSON format
type JSONExporter struct {
	// Writer is the output destination (e.g., os.Stdout, file)
	Writer io.Writer

	// Pretty determines whether to use indented formatting
	Pretty bool
}

// CSVExporter exports results as CSV format
type CSVExporter struct {
	// Writer is the output destination
	Writer io.Writer

	// IncludeHeader determines whether to include CSV header row
	IncludeHeader bool
}

// TableExporter exports results as formatted table (for terminal output)
type TableExporter struct {
	// Writer is the output destination
	Writer io.Writer

	// ColorOutput enables colored output
	ColorOutput bool
}

// GCSExporter exports results to Google Cloud Storage
type GCSExporter struct {
	// BucketName is the GCS bucket name
	BucketName string

	// ObjectPath is the path within the bucket
	ObjectPath string

	// Format specifies the file format (json, csv, etc.)
	Format string
}

// ============================================================================
// CLI Component
// ============================================================================

// Runner represents the main CLI execution interface
type Runner interface {
	// Run executes the CLI with the given arguments
	Run(args []string) error
}
