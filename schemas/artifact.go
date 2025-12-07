package schemas

import (
	"encoding/json"
	"fmt"
	"time"
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
