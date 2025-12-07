package drydock

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/hiro-o918/drydock/schemas"
	"github.com/rs/zerolog/log"
)

// Scanner handles the scanning of container images.
type Scanner struct {
	location    string
	projectID   string
	concurrency uint8
	resolver    *ImageResolver
	analyzer    *ArtifactRegistryAnalyzer
	exporter    Exporter
}

// NewScanner creates a new Scanner instance.
func NewScanner(
	location string,
	projectID string,
	concurrency uint8,
	resolver *ImageResolver,
	analyzer *ArtifactRegistryAnalyzer,
	exporter Exporter,
) *Scanner {
	return &Scanner{
		location:    location,
		projectID:   projectID,
		concurrency: concurrency,
		resolver:    resolver,
		analyzer:    analyzer,
		exporter:    exporter,
	}
}

// scanCollector is a helper struct to manage thread-safe result collection.
// It isolates the mutex logic from the main business logic.
type scanCollector struct {
	mu      sync.Mutex
	results []schemas.AnalyzeResult
	errs    error
}

func (c *scanCollector) addResult(res schemas.AnalyzeResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results = append(c.results, res)
}

func (c *scanCollector) addError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errs = errors.Join(c.errs, err)
}

// Scan iterates over images, analyzes them concurrently, and exports the results.
func (s *Scanner) Scan(ctx context.Context, minSeverity schemas.Severity) error {
	log.Debug().Msg("Resolving images from Artifact Registry...")

	collector := &scanCollector{
		results: make([]schemas.AnalyzeResult, 0),
	}

	// Semaphore to limit concurrency
	sem := make(chan struct{}, s.concurrency)
	var wg sync.WaitGroup

	count := 0

	// 1. Resolve Targets (Producer)
	for target, err := range s.resolver.AllLatestImages(ctx, s.projectID, s.location) {
		if err != nil {
			log.Warn().Err(err).Msg("Error occurred during image resolution stream")
			collector.addError(fmt.Errorf("resolving image stream: %w", err))
			continue
		}
		count++

		// Acquire semaphore (blocks if limit is reached)
		sem <- struct{}{}
		wg.Add(1)

		// 2. Analyze Target (Consumer)
		go func(t ImageTarget) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			s.analyzeTarget(ctx, t, minSeverity, collector)
		}(target)
	}

	// Wait for all analysis jobs to complete
	wg.Wait()

	log.Info().
		Int("targets_found", count).
		Int("scanned_successfully", len(collector.results)).
		Msg("Scan phase completed")

	// 3. Export Results
	if len(collector.results) > 0 {
		log.Info().Msg("Exporting results to stdout...")
		if err := s.exporter.Export(ctx, collector.results); err != nil {
			return fmt.Errorf("failed to export results: %w", err)
		}
	} else {
		log.Warn().Msg("No vulnerabilities found or no images scanned.")
	}

	// 4. Report Partial Errors
	if collector.errs != nil {
		return fmt.Errorf("scan completed with partial errors:\n%w", collector.errs)
	}

	log.Info().Msg("Done")
	return nil
}

// analyzeTarget handles the analysis of a single image target.
func (s *Scanner) analyzeTarget(
	ctx context.Context,
	target ImageTarget,
	minSeverity schemas.Severity,
	collector *scanCollector,
) {
	log.Debug().Str("image", target.Artifact.ImageName).Msg("Analyzing image")

	req := AnalyzeRequest{
		Artifact:    target.Artifact,
		Location:    target.Location,
		MinSeverity: minSeverity,
	}

	result, err := s.analyzer.Analyze(ctx, req)
	if err != nil {
		log.Warn().Err(err).Str("image", target.Artifact.ImageName).Msg("Analysis failed")
		collector.addError(fmt.Errorf("analyzing %s: %w", target.URI, err))
		return
	}

	collector.addResult(*result)
}
