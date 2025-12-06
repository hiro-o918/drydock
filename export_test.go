package drydock

// Export internal functions for black-box testing in analyzer_test package.
var (
	ExportConvertToVulnerability = convertToVulnerability
	ExportFilterBySeverity       = filterBySeverity
	ExportBuildSummary           = buildSummary
	ExportIsDigest               = isDigest
	ExportParseDigestFromURI     = parseDigestFromURI
	ExportSelectBestDigest       = selectBestDigest
)

type ExportCandidateImage = candidateImage
