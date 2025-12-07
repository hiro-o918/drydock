package drydock

import (
	"context"
	"errors"
	"fmt"

	"github.com/hiro-o918/drydock/schemas"
	"github.com/rs/zerolog/log"
)

type Scanner struct {
	location  string
	projectID string
	resolver  *ImageResolver
	analyzer  *ArtifactRegistryAnalyzer
	exporter  Exporter
}

func NewScanner(
	location string,
	projectID string,
	resolver *ImageResolver,
	analyzer *ArtifactRegistryAnalyzer,
	exporter Exporter,
) *Scanner {
	return &Scanner{
		location:  location,
		projectID: projectID,
		resolver:  resolver,
		analyzer:  analyzer,
		exporter:  exporter,
	}
}

func (s *Scanner) Scan(ctx context.Context, minSeverity schemas.Severity) error {
	results := make([]schemas.AnalyzeResult, 0)
	var scanErrs error

	log.Debug().Msg("Resolving images from Artifact Registry...")

	count := 0
	// 1. Resolve Targets
	for target, err := range s.resolver.AllLatestImages(ctx, s.projectID, s.location) {
		if err != nil {
			log.Warn().Err(err).Msg("Error occurred during image resolution stream")
			scanErrs = errors.Join(scanErrs, fmt.Errorf("resolving image stream: %w", err))
			continue
		}
		count++

		// 2. Analyze Target
		log.Debug().Str("image", target.Artifact.ImageName).Msg("Analyzing image")

		req := AnalyzeRequest{
			Artifact:    target.Artifact,
			Location:    target.Location,
			MinSeverity: minSeverity,
		}

		result, err := s.analyzer.Analyze(ctx, req)
		if err != nil {
			log.Warn().Err(err).Str("image", target.Artifact.ImageName).Msg("Analysis failed")
			scanErrs = errors.Join(scanErrs, fmt.Errorf("analyzing %s: %w", target.URI, err))
			continue
		}

		results = append(results, *result)
	}

	log.Info().Int("targets_found", count).Int("scanned_successfully", len(results)).Msg("Scan phase completed")

	// 3. Export Results
	if len(results) > 0 {
		log.Info().Msg("Exporting results to stdout...")
		if err := s.exporter.Export(ctx, results); err != nil {
			return fmt.Errorf("failed to export results: %w", err)
		}
	} else {
		log.Warn().Msg("No vulnerabilities found or no images scanned.")
	}

	// 4. Report Partial Errors
	if scanErrs != nil {
		return fmt.Errorf("scan completed with partial errors:\n%w", scanErrs)
	}

	log.Info().Msg("Done")
	return nil
}
