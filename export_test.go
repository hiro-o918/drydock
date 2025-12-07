package drydock

// Export internal functions for black-box testing in analyzer_test package.
var (
	ExportConvertToVulnerability       = convertToVulnerability
	ExportFilterBySeverity             = filterBySeverity
	ExportBuildSummary                 = buildSummary
	ExportSelectBestDigest             = selectBestDigest
	ExportExtractLocationAndRepository = extractLocationAndRepository
)

type ExportCandidateImage = candidateImage
