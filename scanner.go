package drydock

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/hiro-o918/drydock/schemas"
	"github.com/hiro-o918/drydock/utils"
	"github.com/rs/zerolog/log"
	"google.golang.org/api/option"
)

// Scanner handles the scanning of container images.
type Scanner struct {
	location      string
	projectID     string
	concurrency   uint8
	resolver      *ImageResolver
	analyzer      *ArtifactRegistryAnalyzer
	exporter      Exporter
	clientOptions []option.ClientOption // クライアント作成時のオプション
}

// ScannerOption defines a function type that can configure a Scanner
type ScannerOption func(*Scanner) error

// WithProjectID sets the GCP project ID for the scanner
func WithProjectID(projectID string) ScannerOption {
	return func(s *Scanner) error {
		s.projectID = projectID
		return nil
	}
}

// WithConcurrency sets the concurrency level for parallel scanning
func WithConcurrency(concurrency uint8) ScannerOption {
	return func(s *Scanner) error {
		s.concurrency = concurrency
		return nil
	}
}

// WithResolver sets a custom ImageResolver
func WithResolver(resolver *ImageResolver) ScannerOption {
	return func(s *Scanner) error {
		s.resolver = resolver
		return nil
	}
}

// WithAnalyzer sets a custom Analyzer
func WithAnalyzer(analyzer *ArtifactRegistryAnalyzer) ScannerOption {
	return func(s *Scanner) error {
		s.analyzer = analyzer
		return nil
	}
}

// WithExporter sets a custom Exporter
func WithExporter(exporter Exporter) ScannerOption {
	return func(s *Scanner) error {
		s.exporter = exporter
		return nil
	}
}

// WithOutputFormat sets the output format and creates an appropriate exporter
func WithOutputFormat(format OutputFormat, writer io.Writer) ScannerOption {
	return func(s *Scanner) error {
		exporter, err := NewExporter(format, writer)
		if err != nil {
			return fmt.Errorf("failed to create exporter with format %s: %w", format, err)
		}
		s.exporter = exporter
		return nil
	}
}

// WithClientOptions sets client options for both resolver and analyzer
func WithClientOptions(opts ...option.ClientOption) ScannerOption {
	return func(s *Scanner) error {
		s.clientOptions = opts
		return nil
	}
}

func NewScanner(
	ctx context.Context,
	location string,
	opts ...ScannerOption,
) (*Scanner, error) {
	// Initialize scanner with required fields and default values
	scanner := &Scanner{
		location:      location,
		concurrency:   5,                       // Default concurrency
		clientOptions: []option.ClientOption{}, // 空の配列で初期化
	}

	// Apply all options if provided
	for _, opt := range opts {
		if err := opt(scanner); err != nil {
			return nil, fmt.Errorf("failed to apply scanner option: %w", err)
		}
	}

	// If projectID is still empty after applying options, try to determine it from environment
	if scanner.projectID == "" {
		var err error
		scanner.projectID, err = utils.GetProjectID(ctx)
		if err != nil {
			return nil, fmt.Errorf("project ID is required but was not provided and could not be determined: %w", err)
		}
	}

	// Add project ID to client options if provided
	if scanner.projectID != "" {
		scanner.clientOptions = append(scanner.clientOptions, option.WithQuotaProject(scanner.projectID))
	}

	// Create default components if not provided via options
	var err error

	// Default resolver if not set
	if scanner.resolver == nil {
		scanner.resolver, err = NewImageResolver(ctx, scanner.clientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create default image resolver: %w", err)
		}
	}

	// Default analyzer if not set
	if scanner.analyzer == nil {
		scanner.analyzer, err = NewArtifactRegistryAnalyzer(ctx, scanner.clientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create default analyzer: %w", err)
		}
	}

	// Default exporter if not set
	if scanner.exporter == nil {
		// JSONをデフォルト形式、標準出力をデフォルトwriterとする
		scanner.exporter, err = NewExporter(OutputFormatJSON, os.Stdout)
		if err != nil {
			return nil, fmt.Errorf("failed to create default exporter: %w", err)
		}
	}

	return scanner, nil
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
func (s *Scanner) Scan(ctx context.Context, minSeverity schemas.Severity, fixableOnly bool) error {
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

			s.analyzeTarget(ctx, t, minSeverity, fixableOnly, collector)
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
	fixableOnly bool,
	collector *scanCollector,
) {
	log.Debug().Str("image", target.Artifact.ImageName).Msg("Analyzing image")

	req := AnalyzeRequest{
		Artifact:    target.Artifact,
		Location:    target.Location,
		MinSeverity: minSeverity,
		FixableOnly: fixableOnly,
	}

	result, err := s.analyzer.Analyze(ctx, req)
	if err != nil {
		log.Warn().Err(err).Str("image", target.Artifact.ImageName).Msg("Analysis failed")
		collector.addError(fmt.Errorf("analyzing %s: %w", target.URI, err))
		return
	}

	collector.addResult(*result)
}

// Close releases all resources used by the scanner
func (s *Scanner) Close() error {
	var errs error
	if err := s.resolver.Close(); err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to close resolver: %w", err))
	}

	if err := s.analyzer.Close(); err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to close analyzer: %w", err))
	}

	return errs
}
