package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/hiro-o918/drydock/schemas"
)

// Config holds the application configuration.
type Config struct {
	ProjectID   string
	Location    string
	MinSeverity string
	Debug       bool
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

// parseFlags handles CLI argument parsing and returns a validated Config.
func parseFlags(args []string, stderr io.Writer) (*Config, error) {
	fs := flag.NewFlagSet("drydock", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := &Config{}
	fs.StringVar(&cfg.ProjectID, "project", "", "GCP project ID (required)")
	fs.StringVar(&cfg.Location, "location", "", "Artifact Registry location (required)")
	fs.StringVar(&cfg.MinSeverity, "min-severity", "HIGH", "Minimum severity level (MINIMAL, LOW, MEDIUM, HIGH, CRITICAL)")
	fs.BoolVar(&cfg.Debug, "debug", false, "Enable debug logging")

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
