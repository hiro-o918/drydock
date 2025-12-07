package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/hiro-o918/drydock"
	"github.com/hiro-o918/drydock/schemas"
)

// Config holds the application configuration.
type Config struct {
	ProjectID    string
	Location     string
	MinSeverity  string
	FixableOnly  bool
	OutputFormat drydock.OutputFormat
	Concurrency  uint8
	Debug        bool
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.Location == "" {
		return errors.New("flag `-l`, `--location` is required")
	}
	// OutputFormat validation is handled during flag parsing, so it's not needed here.
	return nil
}

// parseFlags handles CLI argument parsing and returns a validated Config.
func parseFlags(args []string, stderr io.Writer) (*Config, error) {
	if len(args) == 0 {
		args = []string{"-h"}
	}
	fs := flag.NewFlagSet("drydock", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := &Config{
		OutputFormat: drydock.OutputFormatJSON,
		Concurrency:  5, // Default concurrency level
	}

	// --project / -p
	fs.StringVar(&cfg.ProjectID, "project", "", "GCP project ID (required)")
	fs.StringVar(&cfg.ProjectID, "p", "", "Project ID (alias for --project)")

	// --location / -l
	fs.StringVar(&cfg.Location, "location", "", "Artifact Registry location (required)")
	fs.StringVar(&cfg.Location, "l", "", "Location (alias for --location)")

	// --min-severity / -s
	fs.StringVar(&cfg.MinSeverity, "min-severity", "HIGH", "Minimum severity level")
	fs.StringVar(&cfg.MinSeverity, "s", "HIGH", "Severity (alias for --min-severity)")

	// --fixable-only / -f
	fs.BoolVar(&cfg.FixableOnly, "fixable", false, "Only show vulnerabilities that have a fix available")

	// --output-format / -o
	fs.Var(&cfg.OutputFormat, "output-format", "Output format (json, csv, tsv)")
	fs.Var(&cfg.OutputFormat, "o", "Output format (alias for --output-format)")

	// --concurrency / -c
	fs.Func("concurrency", "Number of concurrent scans (default: 5)", func(s string) error {
		var n uint64
		_, err := fmt.Sscanf(s, "%d", &n)
		if err != nil {
			return fmt.Errorf("invalid concurrency value: %w", err)
		}
		if n < 1 {
			return fmt.Errorf("concurrency must be at least 1")
		}
		if n > 255 {
			return fmt.Errorf("concurrency must be at most 255")
		}
		cfg.Concurrency = uint8(n)
		return nil
	})
	fs.Func("c", "Concurrency (alias for --concurrency)", func(s string) error {
		var n uint64
		_, err := fmt.Sscanf(s, "%d", &n)
		if err != nil {
			return fmt.Errorf("invalid concurrency value: %w", err)
		}
		if n < 1 {
			return fmt.Errorf("concurrency must be at least 1")
		}
		if n > 255 {
			return fmt.Errorf("concurrency must be at most 255")
		}
		cfg.Concurrency = uint8(n)
		return nil
	})

	// --debug / -d
	fs.BoolVar(&cfg.Debug, "debug", false, "Enable debug logging")
	fs.BoolVar(&cfg.Debug, "d", false, "Debug (alias for --debug)")

	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Drydock - Artifact Registry Vulnerability Scanner")
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

func parseSeverity(s string) (schemas.Severity, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "MINIMAL":
		return schemas.SeverityMinimal, nil
	case "LOW":
		return schemas.SeverityLow, nil
	case "MEDIUM":
		return schemas.SeverityMedium, nil
	case "HIGH":
		return schemas.SeverityHigh, nil
	case "CRITICAL":
		return schemas.SeverityCritical, nil
	default:
		return "", fmt.Errorf("invalid severity level: %s (allowed: MINIMAL, LOW, MEDIUM, HIGH, CRITICAL)", s)
	}
}
