package drydock

import "time"

// Export internal functions for black-box testing in analyzer_test package.
var (
	ExportConvertToVulnerability       = convertToVulnerability
	ExportFilterBySeverity             = filterBySeverity
	ExportFilterFixable                = filterFixable
	ExportBuildSummary                 = buildSummary
	ExportExtractLocationAndRepository = extractLocationAndRepository
	ExportDedupTargets                 = dedupTargets
	ExportSelectDigests                = selectDigests
	ExportRepositoryAllowed            = repositoryAllowed
	ExportMatchesAnyImagePattern       = matchesAnyImagePattern
	ExportSortedImageNames             = sortedImageNames
)

type ExportCandidateImage = candidateImage

type ExportDigestSelectionOptions = digestSelectionOptions

type ExportScanPolicy = scanPolicy

// NewExportDigestSelectionOptions builds a digestSelectionOptions for tests,
// bridging its unexported fields to the external test package.
func NewExportDigestSelectionOptions(count int, preferTag string, maxAge time.Duration, now time.Time) ExportDigestSelectionOptions {
	return digestSelectionOptions{count: count, preferTag: preferTag, maxAge: maxAge, now: now}
}

// NewExportScanPolicy builds a scanPolicy for tests, bridging its unexported
// fields to the external test package.
func NewExportScanPolicy(
	selection ExportDigestSelectionOptions,
	maxCandidates int,
	includeRepositories, excludeRepositories map[string]struct{},
	imagePatterns []string,
) ExportScanPolicy {
	return scanPolicy{
		selection:           selection,
		maxCandidates:       maxCandidates,
		includeRepositories: includeRepositories,
		excludeRepositories: excludeRepositories,
		imagePatterns:       imagePatterns,
	}
}

// ExportLatestResolverPolicy exposes a LatestResolver's selection policy for
// testing, bridging its unexported field to the external test package.
func ExportLatestResolverPolicy(r *LatestResolver) ExportScanPolicy {
	return r.policy
}
