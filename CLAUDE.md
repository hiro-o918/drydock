# Drydock - Artifact Registry Vulnerability Scanner

## Overview

Drydock is a CLI tool for scanning and reporting vulnerabilities from Google Cloud Artifact Registry. It allows users to query vulnerability information for container images and filter results by severity level.

## Architecture

The system consists of three main components:

```
┌─────────────────┐
│      CLI        │
│  (Entry Point)  │
└────────┬────────┘
         │
         ├──────────────────────────┐
         │                          │
         ▼                          ▼
┌────────────────┐         ┌────────────────┐
│    Analyzer    │────────▶│    Exporter    │
│ (Data Fetcher) │         │  (Formatter)   │
└────────────────┘         └────────────────┘
```

### Component Responsibilities

1. **CLI**: Command-line interface that orchestrates the vulnerability scanning workflow
2. **Analyzer**: Fetches vulnerability data from Artifact Registry and processes it
3. **Exporter**: Abstract interface for outputting vulnerability results in various formats

## Component Design (Interface Level)

All components are defined in a flat package structure following Go best practices. Components are separated by responsibility but reside in the same package initially.

```go
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

// ============================================================================
// CLI Component
// ============================================================================

// Runner represents the main CLI execution interface
type Runner interface {
    // Run executes the CLI with the given arguments
    Run(args []string) error
}

// Config holds the CLI configuration
type Config struct {
    // ProjectID is the GCP project ID
    ProjectID string

    // Location is the Artifact Registry location
    Location string

    // Repository is the Artifact Registry repository name
    Repository string

    // Image is the container image name
    Image string

    // Tag is the image tag
    Tag string

    // MinSeverity is the minimum severity level to report
    MinSeverity Severity

    // OutputFormat specifies the output format
    OutputFormat string
}
```

### Concrete Exporter Implementations

Different exporters are provided for different output formats and destinations. All implementations are in the same package:

```go
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
```

## Data Flow

1. User executes CLI with parameters (project, repository, image, severity level, output format)
2. CLI validates input and creates Config
3. CLI instantiates Analyzer with appropriate credentials
4. **CLI selects and instantiates the appropriate Exporter based on output configuration (DI)**
5. Analyzer connects to Artifact Registry API
6. Analyzer fetches vulnerability scan results
7. Analyzer filters and transforms data into AnalyzeResult
8. CLI invokes Exporter.Export() with the results
9. Exporter formats and outputs the results to its configured destination
10. CLI returns exit code (0 for success, non-zero for errors or if vulnerabilities found)

## Design Principles

### 1. Flat Package Structure
- All components reside in the same package initially (package main)
- Follow Go best practices: start simple, split packages when necessary
- Components are separated by clear interface boundaries
- Package split can be done later if the codebase grows

### 2. Separation of Concerns
- CLI handles user interaction and orchestration
- Analyzer focuses on data fetching and processing
- Exporter handles output formatting and destination
- Clear separation through interfaces, not packages

### 3. Dependency Injection
- Exporter implementation is chosen at initialization time
- Makes testing easier with mock implementations
- Clear separation between configuration and execution

### 4. Interface-Driven Design
- All components are defined by interfaces
- Enables easy testing with mock implementations
- Allows for future extensions (e.g., support for other registries)

### 5. Single Responsibility
- Each component has a clear, focused purpose
- Components can be tested independently
- Changes to one component minimize impact on others

### 6. Open/Closed Principle
- New export formats can be added by creating new implementations
- Analyzer can be extended for different data sources
- No modification to existing code needed for extensions

## Future Considerations

### Package Structure Evolution

As the codebase grows, consider splitting into packages when:
- The main package file exceeds ~1000 lines
- Clear domain boundaries emerge (e.g., separate packages for GCP client, exporters, analyzers)
- Multiple implementations of an interface exist
- Testing becomes cumbersome due to package size

Potential future package structure:
```
drydock/
├── main.go           # CLI entry point
├── analyzer/         # Analyzer interface and implementations
├── exporter/         # Exporter interface and implementations
└── domain/           # Core domain types (Vulnerability, Severity, etc.)
```

### Extensibility Points

1. **Multiple Registry Support**: The Analyzer interface can be extended to support Docker Hub, AWS ECR, etc.
2. **Custom Filters**: Additional filtering logic beyond severity level
3. **Output Formats**: New exporters can be added for different formats (HTML, PDF, YAML, etc.)
4. **Output Destinations**: Additional exporters for S3, Azure Blob Storage, etc.
5. **Caching**: Cache vulnerability data to reduce API calls
6. **Continuous Monitoring**: Schedule periodic scans and track changes over time
7. **Policy Enforcement**: Define policies and fail builds based on vulnerability thresholds
8. **Notification Integration**: Exporters for Slack, email, PagerDuty, etc.

### Error Handling Strategy

- All components return errors following Go best practices
- Context is used for cancellation and timeouts
- Structured error types for different failure scenarios
- Graceful degradation when possible

### Testing Strategy

- Unit tests for each component using interface mocks
- Integration tests for Analyzer against real API (with test projects)
- End-to-end tests for CLI with various scenarios
- Table-driven tests for severity filtering and data transformation
- Test each exporter implementation independently
