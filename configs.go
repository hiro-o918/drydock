package drydock

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
