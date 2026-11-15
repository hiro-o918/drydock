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
)

type ExportCandidateImage = candidateImage

type ExportDigestSelectionOptions = digestSelectionOptions

// NewExportDigestSelectionOptions builds a digestSelectionOptions for tests,
// bridging its unexported fields to the external test package.
func NewExportDigestSelectionOptions(count int, preferTag string, maxAge time.Duration, now time.Time) ExportDigestSelectionOptions {
	return digestSelectionOptions{count: count, preferTag: preferTag, maxAge: maxAge, now: now}
}
