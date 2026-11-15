package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/hiro-o918/drydock"
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
	// Preliminary Logger Setup (in case of early errors)
	setupGlobalLogger(stderr, false)

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

	// 4. Execution Phase
	log.Info().Msg("Starting vulnerability scan...")

	// Create scanner options
	var scannerOpts []drydock.ScannerOption
	if cfg.ProjectID != "" {
		scannerOpts = append(scannerOpts, drydock.WithProjectID(cfg.ProjectID))
	}
	scannerOpts = append(scannerOpts, drydock.WithConcurrency(cfg.Concurrency))
	scannerOpts = append(scannerOpts, drydock.WithClientOptions(clientOpts...))
	scannerOpts = append(scannerOpts, drydock.WithOutputFormat(cfg.OutputFormat, stdout))

	targetOpt, err := targetResolverOption(cfg)
	if err != nil {
		return fmt.Errorf("invalid target configuration: %w", err)
	}
	scannerOpts = append(scannerOpts, targetOpt)

	// Initialize scanner with location and options
	scanner, err := drydock.NewScanner(ctx, cfg.Location, scannerOpts...)
	if err != nil {
		return fmt.Errorf("failed to initialize scanner: %w", err)
	}
	defer func() {
		if err := scanner.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close scanner resources")
		}
	}()

	minSeverity, err := parseSeverity(cfg.MinSeverity)
	if err != nil {
		return fmt.Errorf("invalid minimum severity: %w", err)
	}

	if err := scanner.Scan(ctx, minSeverity, cfg.FixableOnly); err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	log.Info().Msg("Vulnerability scan completed successfully")
	return nil
}

// targetResolverOption builds the ScannerOption controlling which digests to
// scan. --digest takes precedence over the discovery-tuning flags, since it
// is meant to replace discovery entirely with explicit, pinned images.
func targetResolverOption(cfg *Config) (drydock.ScannerOption, error) {
	if len(cfg.Digests) > 0 {
		if cfg.Latest != 1 || len(cfg.Repositories) > 0 || len(cfg.ExcludeRepositories) > 0 || len(cfg.ImageFilters) > 0 || cfg.MaxAge > 0 {
			log.Debug().Msg("--digest set; ignoring --latest, --repository, --exclude-repository, --image-filter and --max-age")
		}

		targets, err := buildStaticTargets(cfg.Digests, cfg.Location)
		if err != nil {
			return nil, err
		}
		return drydock.WithTargetResolver(drydock.NewStaticResolver(targets...)), nil
	}

	return drydock.WithLatestResolverOptions(newLatestDiscoveryConfig(cfg).toOptions()...), nil
}

// buildStaticTargets parses each digest (tag or digest image reference)
// into an ImageTarget for StaticResolver.
func buildStaticTargets(digests []string, location string) ([]drydock.ImageTarget, error) {
	targets := make([]drydock.ImageTarget, 0, len(digests))
	for _, d := range digests {
		ref, err := drydock.ParseArtifactURI(d)
		if err != nil {
			return nil, fmt.Errorf("invalid --digest value %q: %w", d, err)
		}
		targets = append(targets, drydock.ImageTarget{
			Artifact: ref,
			URI:      d,
			Location: location,
		})
	}
	return targets, nil
}

// latestDiscoveryConfig is the pure, comparable representation of which
// LatestResolverOptions to apply. It is kept separate from the
// drydock.LatestResolverOption closures it builds (which cannot be compared
// in tests) so the CLI-flag-to-policy mapping stays directly testable.
type latestDiscoveryConfig struct {
	count               int
	repositories        []string
	excludeRepositories []string
	imageFilters        []string
	maxAge              time.Duration
}

func newLatestDiscoveryConfig(cfg *Config) latestDiscoveryConfig {
	c := latestDiscoveryConfig{count: cfg.Latest}
	if len(cfg.Repositories) > 0 {
		c.repositories = cfg.Repositories
	}
	if len(cfg.ExcludeRepositories) > 0 {
		c.excludeRepositories = cfg.ExcludeRepositories
	}
	if len(cfg.ImageFilters) > 0 {
		c.imageFilters = cfg.ImageFilters
	}
	if cfg.MaxAge > 0 {
		c.maxAge = cfg.MaxAge
	}
	return c
}

func (c latestDiscoveryConfig) toOptions() []drydock.LatestResolverOption {
	opts := []drydock.LatestResolverOption{drydock.WithLatestCount(c.count)}
	if len(c.repositories) > 0 {
		opts = append(opts, drydock.WithRepositories(c.repositories...))
	}
	if len(c.excludeRepositories) > 0 {
		opts = append(opts, drydock.WithExcludeRepositories(c.excludeRepositories...))
	}
	if len(c.imageFilters) > 0 {
		opts = append(opts, drydock.WithImageFilter(c.imageFilters...))
	}
	if c.maxAge > 0 {
		opts = append(opts, drydock.WithMaxAge(c.maxAge))
	}
	return opts
}
