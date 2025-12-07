package exporter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hiro-o918/drydock/exporter"
	"github.com/hiro-o918/drydock/schemas"
	"github.com/hiro-o918/drydock/utils"
)

func TestJSONExporter_Export(t *testing.T) {
	now := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)

	validResult := []schemas.AnalyzeResult{{
		Artifact: schemas.ArtifactReference{
			Host:         "us-central1-docker.pkg.dev",
			ProjectID:    "project",
			RepositoryID: "repo",
			ImageName:    "image",
			Digest:       utils.ToPtr("sha256:abc123"),
		},
		ScanTime: now,
		Vulnerabilities: []schemas.Vulnerability{
			{
				ID:               "CVE-2023-0001",
				Severity:         schemas.SeverityHigh,
				PackageName:      "openssl",
				InstalledVersion: "1.1.1",
				FixedVersion:     "1.1.1t",
				Description:      "Sample vulnerability",
				CVSSScore:        7.5,
				URLs:             []string{"https://cve.mitre.org/example"},
			},
		},
		Summary: schemas.VulnerabilitySummary{
			TotalCount:   1,
			FixableCount: 1,
			CountBySeverity: map[schemas.Severity]int{
				schemas.SeverityHigh: 1,
			},
		},
	},
	}

	emptyResult := []schemas.AnalyzeResult{{
		Artifact: schemas.ArtifactReference{
			Host:         "us-central1-docker.pkg.dev",
			ProjectID:    "project",
			RepositoryID: "repo",
			ImageName:    "image",
			Digest:       utils.ToPtr("sha256:abc123"),
		},
		ScanTime:        now,
		Vulnerabilities: []schemas.Vulnerability{},
		Summary: schemas.VulnerabilitySummary{
			TotalCount:      0,
			FixableCount:    0,
			CountBySeverity: map[schemas.Severity]int{},
		},
	},
	}

	tests := map[string]struct {
		results  []schemas.AnalyzeResult
		validate func(t *testing.T, output string)
		wantErr  bool
	}{
		"should export valid result with indentation": {
			results: validResult,
			validate: func(t *testing.T, output string) {
				// Verify indentation exists
				if !strings.Contains(output, "\n  ") {
					t.Error("Expected indented JSON but got compact format")
				}

				// Verify key fields are present
				expectedFields := []string{
					`"Artifact"`,
					`"ScanTime"`,
					`"Vulnerabilities"`,
					`"Summary"`,
					`"CVE-2023-0001"`,
					`"openssl"`,
				}
				for _, field := range expectedFields {
					if !strings.Contains(output, field) {
						t.Errorf("Expected output to contain %s", field)
					}
				}

				// Verify output ends with newline
				if !strings.HasSuffix(output, "\n") {
					t.Error("Expected output to end with newline")
				}

				// Verify JSON structure by unmarshaling
				var unmarshaled []schemas.AnalyzeResult
				if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &unmarshaled); err != nil {
					t.Fatalf("Failed to unmarshal JSON: %v", err)
				}

				if diff := cmp.Diff(validResult, unmarshaled); diff != "" {
					t.Errorf("Unmarshaled result mismatch (-want +got):\n%s", diff)
				}
			},
		},
		"should handle empty vulnerabilities list": {
			results: emptyResult,
			validate: func(t *testing.T, output string) {
				// Verify empty array is properly represented
				if !strings.Contains(output, `"Vulnerabilities": []`) {
					t.Error("Expected empty Vulnerabilities array")
				}

				// Verify JSON structure by unmarshaling
				var unmarshaled []schemas.AnalyzeResult
				if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &unmarshaled); err != nil {
					t.Fatalf("Failed to unmarshal JSON: %v", err)
				}

				if diff := cmp.Diff(emptyResult, unmarshaled); diff != "" {
					t.Errorf("Unmarshaled result mismatch (-want +got):\n%s", diff)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			exp := exporter.NewJSONExporter(&buf)

			err := exp.Export(context.Background(), tt.results)
			if (err != nil) != tt.wantErr {
				t.Errorf("Export() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.validate != nil {
				tt.validate(t, buf.String())
			}
		})
	}
}
