package drydock

import (
	"context"
	"fmt"
	"time"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	"github.com/hiro-o918/drydock/schemas"
	"github.com/rs/zerolog/log"
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
func (a *ArtifactRegistryAnalyzer) Analyze(ctx context.Context, req AnalyzeRequest) (*schemas.AnalyzeResult, error) {
	// Generate resource URL using ArtifactReference method
	resourceURL := req.Artifact.ToResourceURL(req.Location)

	// Obtain the Grafeas client from the Container Analysis client.
	grafeasClient := a.containerAnalysisClient.GetGrafeasClient()

	// Filter specifically for vulnerabilities attached to this resource URL.
	listReq := &grafeaspb.ListOccurrencesRequest{
		Parent: fmt.Sprintf("projects/%s", req.Artifact.ProjectID),
		Filter: fmt.Sprintf(`resourceUrl="%s" AND kind="VULNERABILITY"`, resourceURL),
	}

	it := grafeasClient.ListOccurrences(ctx, listReq)
	vulnerabilities := make([]schemas.Vulnerability, 0)

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

	// Filter by fixability if requested
	if req.FixableOnly {
		filtered = filterFixable(filtered)
	}

	return &schemas.AnalyzeResult{
		Artifact:        req.Artifact,
		ScanTime:        time.Now(),
		Vulnerabilities: filtered,
		Summary:         buildSummary(filtered),
	}, nil
}

// Internal Helper Functions

func convertToVulnerability(occ *grafeaspb.Occurrence) (schemas.Vulnerability, error) {
	vulnDetails := occ.GetVulnerability()
	// Initialize variables for package details
	var pkgName string
	var installedVer string
	var fixedVer string
	var packageType string

	// Extract details from PackageIssue
	// We primarily use the first issue found to determine package metadata.
	if issues := vulnDetails.GetPackageIssue(); len(issues) > 0 {
		issue := issues[0]
		pkgName = issue.AffectedPackage

		// 1. Extract the specific 'package_type' (e.g., "OS", "GO", "MAVEN") if available.
		packageType = issue.GetPackageType()

		if ver := issue.AffectedVersion; ver != nil {
			installedVer = fmt.Sprintf("%s (Kind: %s)", ver.Name, ver.Kind)
		}

		if fixed := issue.FixedVersion; fixed != nil {
			fixedVer = fixed.Name
		}
	}

	vuln := schemas.Vulnerability{
		ID:               vulnDetails.ShortDescription,
		Severity:         convertSeverity(vulnDetails.Severity),
		CVSSScore:        vulnDetails.CvssScore,
		URLs:             convertUrls(vulnDetails.GetRelatedUrls()),
		Description:      occ.NoteName, // Using NoteName as a fallback for description/identifier
		PackageType:      packageType,
		PackageName:      pkgName,
		InstalledVersion: installedVer,
		FixedVersion:     fixedVer,
	}

	return vuln, nil
}

func convertSeverity(s grafeaspb.Severity) schemas.Severity {
	switch s {
	case grafeaspb.Severity_MINIMAL:
		return schemas.SeverityMinimal
	case grafeaspb.Severity_LOW:
		return schemas.SeverityLow
	case grafeaspb.Severity_MEDIUM:
		return schemas.SeverityMedium
	case grafeaspb.Severity_HIGH:
		return schemas.SeverityHigh
	case grafeaspb.Severity_CRITICAL:
		return schemas.SeverityCritical
	default:
		return schemas.SeverityUnspecified
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

func filterBySeverity(vulns []schemas.Vulnerability, min schemas.Severity) []schemas.Vulnerability {
	if min == schemas.SeverityUnspecified {
		return vulns
	}

	levels := map[schemas.Severity]int{
		schemas.SeverityUnspecified: 0,
		schemas.SeverityMinimal:     1,
		schemas.SeverityLow:         2,
		schemas.SeverityMedium:      3,
		schemas.SeverityHigh:        4,
		schemas.SeverityCritical:    5,
	}

	threshold := levels[min]
	filtered := make([]schemas.Vulnerability, 0)

	for _, v := range vulns {
		log.Debug().Str("vulnerability_id", v.ID).
			Str("severity", string(v.Severity)).
			Int("severity_level", levels[v.Severity]).
			Int("threshold_level", threshold).
			Msg("Evaluating vulnerability for severity filter")
		if levels[v.Severity] >= threshold {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func filterFixable(vulns []schemas.Vulnerability) []schemas.Vulnerability {
	filtered := make([]schemas.Vulnerability, 0)

	for _, v := range vulns {
		if v.FixedVersion != "" {
			filtered = append(filtered, v)
		}
	}

	return filtered
}

func buildSummary(vulns []schemas.Vulnerability) schemas.VulnerabilitySummary {
	summary := schemas.VulnerabilitySummary{
		TotalCount:      len(vulns),
		CountBySeverity: make(map[schemas.Severity]int),
	}

	for _, v := range vulns {
		summary.CountBySeverity[v.Severity]++
		if v.FixedVersion != "" {
			summary.FixableCount++
		}
	}
	return summary
}
