package drydock

import (
	"context"
	"fmt"
	"time"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
)

// ArtifactRegistryAnalyzer implements the vulnerability analysis logic.
type ArtifactRegistryAnalyzer struct {
	containerAnalysisClient *containeranalysis.Client
}

// NewArtifactRegistryAnalyzer creates a new analyzer with ADC authentication.
func NewArtifactRegistryAnalyzer(ctx context.Context, opts ...option.ClientOption) (*ArtifactRegistryAnalyzer, error) {
	caClient, err := containeranalysis.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Container Analysis client: %w", err)
	}

	return &ArtifactRegistryAnalyzer{
		containerAnalysisClient: caClient,
	}, nil
}

// Close closes the underlying API client.
func (a *ArtifactRegistryAnalyzer) Close() error {
	return a.containerAnalysisClient.Close()
}

// Analyze retrieves and filters vulnerabilities for the specified image digest.
func (a *ArtifactRegistryAnalyzer) Analyze(ctx context.Context, req AnalyzeRequest) (*AnalyzeResult, error) {
	if req.Digest == "" {
		return nil, fmt.Errorf("digest is required for analysis")
	}

	// Construct the Resource URL. This acts as the search key in Container Analysis.
	// Format must be: https://LOCATION-docker.pkg.dev/PROJECT/REPO/IMAGE@DIGEST
	resourceURL := fmt.Sprintf("https://%s-docker.pkg.dev/%s/%s/%s@%s",
		req.Location, req.ProjectID, req.Repository, req.Image, req.Digest)

	// Obtain the Grafeas client from the Container Analysis client.
	grafeasClient := a.containerAnalysisClient.GetGrafeasClient()

	// Filter specifically for vulnerabilities attached to this resource URL.
	listReq := &grafeaspb.ListOccurrencesRequest{
		Parent: fmt.Sprintf("projects/%s", req.ProjectID),
		Filter: fmt.Sprintf(`resourceUrl="%s" AND kind="VULNERABILITY"`, resourceURL),
	}

	it := grafeasClient.ListOccurrences(ctx, listReq)
	vulnerabilities := make([]Vulnerability, 0)

	for {
		occ, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list occurrences: %w", err)
		}

		vuln, err := convertToVulnerability(occ)
		if err != nil {
			// Skip occurrences that cannot be converted.
			continue
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	filtered := filterBySeverity(vulnerabilities, req.MinSeverity)

	return &AnalyzeResult{
		ImageRef:        resourceURL,
		ScanTime:        time.Now(),
		Vulnerabilities: filtered,
		Summary:         buildSummary(filtered),
	}, nil
}

// Internal Helper Functions

func convertToVulnerability(occ *grafeaspb.Occurrence) (Vulnerability, error) {
	vulnDetails := occ.GetVulnerability()
	if vulnDetails == nil {
		return Vulnerability{}, fmt.Errorf("occurrence does not contain vulnerability details")
	}

	vuln := Vulnerability{
		ID:        vulnDetails.ShortDescription,
		Severity:  convertSeverity(vulnDetails.Severity),
		CVSSScore: vulnDetails.CvssScore,
		URLs:      convertUrls(vulnDetails.GetRelatedUrls()),
		// Using NoteName as a fallback for description/identifier
		Description: occ.NoteName,
	}

	// Extract package issues (current standard field)
	if issues := vulnDetails.GetPackageIssue(); len(issues) > 0 {
		issue := issues[0]
		vuln.PackageName = issue.AffectedPackage

		if ver := issue.AffectedVersion; ver != nil {
			vuln.InstalledVersion = fmt.Sprintf("%s (Kind: %s)", ver.Name, ver.Kind)
		}

		if fixed := issue.FixedVersion; fixed != nil {
			vuln.FixedVersion = fixed.Name
		}
	}

	return vuln, nil
}

func convertSeverity(s grafeaspb.Severity) Severity {
	switch s {
	case grafeaspb.Severity_MINIMAL:
		return SeverityMinimal
	case grafeaspb.Severity_LOW:
		return SeverityLow
	case grafeaspb.Severity_MEDIUM:
		return SeverityMedium
	case grafeaspb.Severity_HIGH:
		return SeverityHigh
	case grafeaspb.Severity_CRITICAL:
		return SeverityCritical
	default:
		return SeverityUnspecified
	}
}

func convertUrls(urls []*grafeaspb.RelatedUrl) []string {
	result := make([]string, 0, len(urls))
	for _, u := range urls {
		if u != nil {
			result = append(result, u.Url)
		}
	}
	return result
}

func filterBySeverity(vulns []Vulnerability, min Severity) []Vulnerability {
	if min == SeverityUnspecified {
		return vulns
	}

	levels := map[Severity]int{
		SeverityUnspecified: 0,
		SeverityMinimal:     1,
		SeverityLow:         2,
		SeverityMedium:      3,
		SeverityHigh:        4,
		SeverityCritical:    5,
	}

	threshold := levels[min]
	filtered := make([]Vulnerability, 0)

	for _, v := range vulns {
		if levels[v.Severity] >= threshold {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func buildSummary(vulns []Vulnerability) VulnerabilitySummary {
	summary := VulnerabilitySummary{
		TotalCount:      len(vulns),
		CountBySeverity: make(map[Severity]int),
	}

	for _, v := range vulns {
		summary.CountBySeverity[v.Severity]++
		if v.FixedVersion != "" {
			summary.FixableCount++
		}
	}
	return summary
}
