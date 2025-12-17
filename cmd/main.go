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
