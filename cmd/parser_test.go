package main

import (
	"io"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hiro-o918/drydock"
	"github.com/hiro-o918/drydock/schemas"
)

func TestParseSeverity(t *testing.T) {
	tests := map[string]struct {
		input   string
		want    schemas.Severity
		wantErr bool
	}{
		"should parse MINIMAL severity": {
			input: "MINIMAL",
			want:  schemas.SeverityMinimal,
		},
		"should parse LOW severity": {
			input: "LOW",
			want:  schemas.SeverityLow,
		},
		"should parse MEDIUM severity": {
			input: "MEDIUM",
			want:  schemas.SeverityMedium,
		},
		"should parse HIGH severity": {
			input: "HIGH",
			want:  schemas.SeverityHigh,
		},
		"should parse CRITICAL severity": {
			input: "CRITICAL",
			want:  schemas.SeverityCritical,
		},
		"should return error when severity is invalid": {
			input:   "INVALID",
			wantErr: true,
		},
		"should return error when severity is empty": {
			input:   "",
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parseSeverity(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSeverity() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseSeverity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseFlags(t *testing.T) {
	tests := map[string]struct {
		args    []string
		want    *Config
		wantErr bool
	}{
		"should default to one digest per image when discovery flags are omitted": {
			args: []string{"-l", "us-central1"},
			want: &Config{
				Location:     "us-central1",
				MinSeverity:  "HIGH",
				OutputFormat: drydock.OutputFormatJSON,
				Concurrency:  5,
				Latest:       1,
			},
		},
		"should collect repeated repository, exclude-repository, image-filter and digest flags": {
			args: []string{
				"-l", "us-central1",
				"--latest", "3",
				"--repository", "repo-a",
				"--repository", "repo-b",
				"--exclude-repository", "repo-c",
				"--image-filter", "service/*",
				"--max-age", "24h",
				"--digest", "us-central1-docker.pkg.dev/p/r/img@sha256:aaa",
				"--digest", "us-central1-docker.pkg.dev/p/r/img2@sha256:bbb",
			},
			want: &Config{
				Location:            "us-central1",
				MinSeverity:         "HIGH",
				OutputFormat:        drydock.OutputFormatJSON,
				Concurrency:         5,
				Latest:              3,
				Repositories:        []string{"repo-a", "repo-b"},
				ExcludeRepositories: []string{"repo-c"},
				ImageFilters:        []string{"service/*"},
				MaxAge:              24 * time.Hour,
				Digests: []string{
					"us-central1-docker.pkg.dev/p/r/img@sha256:aaa",
					"us-central1-docker.pkg.dev/p/r/img2@sha256:bbb",
				},
			},
		},
		"should return error when latest is less than one": {
			args:    []string{"-l", "us-central1", "--latest", "0"},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parseFlags(tt.args, io.Discard)

			if (err != nil) != tt.wantErr {
				t.Fatalf("parseFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("parseFlags() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
