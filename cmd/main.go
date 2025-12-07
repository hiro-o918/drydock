package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/hiro-o918/drydock"
	"github.com/hiro-o918/drydock/exporter"
	"github.com/hiro-o918/drydock/schemas"
	"github.com/rs/zerolog/log"
	"google.golang.org/api/option"
)

func main() {
	ctx := context.Background()

	// Trap Ctrl+C (SIGINT)
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()

	// We use stderr for logging to keep stdout clean for data output.
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		log.Error().Err(err).Msg("Application execution failed")
		os.Exit(1)
	}
}

// run orchestrates the application components.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	// 1. Parse Configuration
	cfg, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	// 2. Setup Logger
	setupGlobalLogger(stderr, cfg.Debug)

	log.Debug().Interface("config", cfg).Msg("Configuration loaded")
	log.Info().Str("project", cfg.ProjectID).Str("location", cfg.Location).Msg("Initializing scanner...")

	// 3. Setup Infrastructure (Clients)
	clientOpts := []option.ClientOption{}
	if cfg.ProjectID != "" {
		clientOpts = append(clientOpts, option.WithQuotaProject(cfg.ProjectID))
	}

	// Initialize Image Resolver
	resolver, err := drydock.NewImageResolver(ctx, clientOpts...)
	if err != nil {
		return fmt.Errorf("failed to initialize image resolver: %w", err)
	}
	defer func() {
		if err := resolver.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close resolver")
		}
	}()

	// Initialize Analyzer
	analyzer, err := drydock.NewArtifactRegistryAnalyzer(ctx, clientOpts...)
	if err != nil {
		return fmt.Errorf("failed to initialize analyzer: %w", err)
	}
	defer func() {
		if err := analyzer.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close analyzer")
		}
	}()

	// Initialize Exporter (Output to stdout)
	resultExporter := exporter.NewJSONExporter(stdout)

	// 4. Execution Phase
	log.Info().Msg("Starting vulnerability scan...")
	return executeScan(ctx, cfg, resolver, analyzer, resultExporter)
}

// executeScan contains the core business logic pipeline.
func executeScan(
	ctx context.Context,
	cfg *Config,
	resolver *drydock.ImageResolver,
	analyzer *drydock.ArtifactRegistryAnalyzer,
	exp drydock.Exporter,
) error {
	minSeverity, err := parseSeverity(cfg.MinSeverity)
	if err != nil {
		return err
	}

	results := make([]schemas.AnalyzeResult, 0)
	var scanErrs error

	log.Debug().Msg("Resolving images from Artifact Registry...")

	count := 0
	// 1. Resolve Targets
	for target, err := range resolver.AllLatestImages(ctx, cfg.ProjectID, cfg.Location) {
		if err != nil {
			log.Warn().Err(err).Msg("Error occurred during image resolution stream")
			scanErrs = errors.Join(scanErrs, fmt.Errorf("resolving image stream: %w", err))
			continue
		}
		count++

		// 2. Analyze Target
		log.Debug().Str("image", target.Artifact.ImageName).Msg("Analyzing image")

		req := drydock.AnalyzeRequest{
			Artifact:    target.Artifact,
			Location:    target.Location,
			MinSeverity: minSeverity,
		}

		result, err := analyzer.Analyze(ctx, req)
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
		if err := exp.Export(ctx, results); err != nil {
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
