package drydock

import (
	"context"
	"encoding/json"
	"fmt"
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
	// Artifact is the image reference to analyze
	Artifact ArtifactReference

	// Location is the GCP location (required for resource URL generation)
	Location string

	// MinSeverity filters vulnerabilities by minimum severity
	MinSeverity Severity
}

// AnalyzeResult contains the analysis results
type AnalyzeResult struct {
	// Artifact is the analyzed image reference
	Artifact ArtifactReference

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
	Host         string  `json:"host"`             // e.g., region-docker.pkg.dev
	ProjectID    string  `json:"projectID"`        // e.g., my-project-id
	RepositoryID string  `json:"repositoryID"`     // e.g., my-app-repo
	ImageName    string  `json:"imageName"`        // e.g., my-service/worker
	Tag          *string `json:"tag,omitempty"`    // e.g., v1.0.0 (nil if not present)
	Digest       *string `json:"digest,omitempty"` // e.g., sha256:e3b0... (nil if not present)
}

// ToResourceURL generates the resource URL for Container Analysis API
func (a ArtifactReference) ToResourceURL(location string) string {
	digestStr := ""
	if a.Digest != nil {
		digestStr = *a.Digest
	}
	return fmt.Sprintf("https://%s-docker.pkg.dev/%s/%s/%s@%s",
		location, a.ProjectID, a.RepositoryID, a.ImageName, digestStr)
}

// String returns a human-readable string representation
func (a ArtifactReference) String() string {
	ref := fmt.Sprintf("%s/%s/%s/%s",
		a.Host, a.ProjectID, a.RepositoryID, a.ImageName)

	if a.Tag != nil {
		ref += ":" + *a.Tag
	}
	if a.Digest != nil {
		ref += "@" + *a.Digest
	}
	return ref
}

// MarshalJSON customizes JSON output to include both structured fields and a URI string
func (a ArtifactReference) MarshalJSON() ([]byte, error) {
	type Alias ArtifactReference
	return json.Marshal(&struct {
		*Alias
		URI string `json:"uri"`
	}{
		Alias: (*Alias)(&a),
		URI:   a.String(),
	})
}
