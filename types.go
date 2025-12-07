package drydock

import (
	"context"
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
	CVSSScore float32

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

	// Digest is the image digest (SHA256)
	Digest string

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
	Export(ctx context.Context, results []AnalyzeResult) error
}

type OutputFormat string

const (
	OutputFormatJSON OutputFormat = "json"
)

// ArtifactReference represents the parsed components of a Google Artifact Registry URI.
type ArtifactReference struct {
	Host         string  // e.g., region-docker.pkg.dev
	ProjectID    string  // e.g., my-project-id
	RepositoryID string  // e.g., my-app-repo
	ImageName    string  // e.g., my-service/worker
	Tag          *string // e.g., v1.0.0 (nil if not present)
	Digest       *string // e.g., sha256:e3b0... (nil if not present)
}
