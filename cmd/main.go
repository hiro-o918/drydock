package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/hiro-o918/drydock"
	"github.com/hiro-o918/drydock/exporter"
	"google.golang.org/api/option"
)

// Config holds the application configuration.
type Config struct {
	ProjectID   string
	Location    string
	MinSeverity string
	// Future: OutputFormat string (json, table, csv)
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.ProjectID == "" {
		return errors.New("flag -project is required")
	}
	if c.Location == "" {
		return errors.New("flag -location is required")
	}
	return nil
}

func main() {
	ctx := context.Background()

	// Trap Ctrl+C (SIGINT)
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()

	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		// Only print error here. We rely on standard library formatting.
		// Explicitly ignoring the return value of Fprintf to satisfy linter in this specific exit block.
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// run orchestrates the application components.
// It handles Dependency Injection and Resource Lifecycle (Defer).
func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	// 1. Parse and Validate Configuration
	cfg, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	// 2. Setup Infrastructure (Clients)
	clientOpts := []option.ClientOption{}
	if cfg.ProjectID != "" {
		clientOpts = append(clientOpts, option.WithQuotaProject(cfg.ProjectID))
	}

	// Initialize Image Resolver (Discovery Phase)
	resolver, err := drydock.NewImageResolver(ctx, clientOpts...)
	if err != nil {
		return fmt.Errorf("failed to initialize image resolver: %w", err)
	}
	// Linter Fix: Handle error in defer
	defer func() {
		if err := resolver.Close(); err != nil {
			_, _ = fmt.Fprintf(stderr, "warning: failed to close resolver: %v\n", err)
		}
	}()

	// Initialize Analyzer (Data Fetching Phase)
	analyzer, err := drydock.NewArtifactRegistryAnalyzer(ctx, clientOpts...)
	if err != nil {
		return fmt.Errorf("failed to initialize analyzer: %w", err)
	}
	// Linter Fix: Handle error in defer
	defer func() {
		if err := analyzer.Close(); err != nil {
			_, _ = fmt.Fprintf(stderr, "warning: failed to close analyzer: %v\n", err)
		}
	}()

	// Initialize Exporter (Formatting Phase)
	// We inject the writer (stdout) here to keep the Exporter testable.
	resultExporter := exporter.NewJSONExporter(stdout)

	// 3. Execution Phase
	return executeScan(ctx, cfg, resolver, analyzer, resultExporter)
}

// parseFlags handles CLI argument parsing and returns a validated Config.
func parseFlags(args []string, stderr io.Writer) (*Config, error) {
	fs := flag.NewFlagSet("drydock", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := &Config{}
	fs.StringVar(&cfg.ProjectID, "project", "", "GCP project ID (required)")
	fs.StringVar(&cfg.Location, "location", "", "Artifact Registry location (required)")
	fs.StringVar(&cfg.MinSeverity, "min-severity", "HIGH", "Minimum severity level (MINIMAL, LOW, MEDIUM, HIGH, CRITICAL)")

	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Drydock - Artifact Registry Vulnerability Scanner")
		_, _ = fmt.Fprintln(stderr, "\nUsage:")
		_, _ = fmt.Fprintln(stderr, "  drydock -project <ID> -location <REGION> [options]")
		_, _ = fmt.Fprintln(stderr, "\nOptions:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		fs.Usage()
		return nil, fmt.Errorf("configuration error: %w", err)
	}

	return cfg, nil
}

// executeScan contains the core business logic pipeline.
// It is pure logic and does not depend on os.Args or global flags.
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

	results := make([]drydock.AnalyzeResult, 0)
	var scanErrs error // Aggregated errors

	// 1. Resolve Targets
	for target, err := range resolver.AllLatestImages(ctx, cfg.ProjectID, cfg.Location) {
		if err != nil {
			// Aggregate errors instead of immediate exit
			scanErrs = errors.Join(scanErrs, fmt.Errorf("resolving %s: %w", target.URI, err))
			continue
		}

		// 2. Analyze Target
		req := drydock.AnalyzeRequest{
			ProjectID:   cfg.ProjectID,
			Location:    target.Location,
			Repository:  target.Repository,
			Image:       target.ImageName,
			Digest:      target.Digest,
			MinSeverity: minSeverity,
		}

		result, err := analyzer.Analyze(ctx, req)
		if err != nil {
			scanErrs = errors.Join(scanErrs, fmt.Errorf("analyzing %s: %w", target.URI, err))
			continue
		}

		results = append(results, *result)
	}

	// 3. Export Results
	if len(results) > 0 {
		if err := exp.Export(ctx, results); err != nil {
			return fmt.Errorf("failed to export results: %w", err)
		}
	}

	// 4. Report Partial Errors
	// We return the aggregated errors at the end.
	// This replaces the manual `fmt.Fprintf` loop that caused linter errors.
	if scanErrs != nil {
		return fmt.Errorf("scan completed with errors:\n%w", scanErrs)
	}

	return nil
}

func parseSeverity(s string) (drydock.Severity, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "MINIMAL":
		return drydock.SeverityMinimal, nil
	case "LOW":
		return drydock.SeverityLow, nil
	case "MEDIUM":
		return drydock.SeverityMedium, nil
	case "HIGH":
		return drydock.SeverityHigh, nil
	case "CRITICAL":
		return drydock.SeverityCritical, nil
	default:
		return "", fmt.Errorf("invalid severity level: %s (allowed: MINIMAL, LOW, MEDIUM, HIGH, CRITICAL)", s)
	}
}
