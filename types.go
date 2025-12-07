package drydock

import (
	"context"

	"github.com/hiro-o918/drydock/schemas"
)

// ============================================================================
// Analyzer Component
// ============================================================================

// Analyzer fetches and processes vulnerability data
type Analyzer interface {
	// Analyze retrieves vulnerabilities for the specified image
	Analyze(ctx context.Context, req AnalyzeRequest) (*schemas.AnalyzeResult, error)
}

// AnalyzeRequest contains parameters for vulnerability analysis
type AnalyzeRequest struct {
	// Artifact is the image reference to analyze
	Artifact schemas.ArtifactReference

	// Location is the GCP location (required for resource URL generation)
	Location string

	// MinSeverity filters vulnerabilities by minimum severity
	MinSeverity schemas.Severity
}

// ============================================================================
// Exporter Component
// ============================================================================

type OutputFormat string

const (
	OutputFormatJSON OutputFormat = "json"
	OutputFormatCSV  OutputFormat = "csv"
	OutputFormatTSV  OutputFormat = "tsv"
)

// Exporter defines the interface for exporting analysis results
type Exporter interface {
	// Export outputs the analysis results to the configured destination
	Export(ctx context.Context, results []schemas.AnalyzeResult) error
}
