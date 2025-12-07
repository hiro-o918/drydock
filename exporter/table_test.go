package exporter_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"          // 実際のモジュールパス
	"github.com/hiro-o918/drydock/exporter" // 実際のモジュールパス
	"github.com/hiro-o918/drydock/schemas"
)

// TestTableExporter_Export_CSV verifies the data transformation logic using CSV format.
// Since the logic (buildRecord) is shared, this covers the core business rules.
func TestTableExporter_Export_CSV(t *testing.T) {
	// Fixed timestamp for deterministic testing
	fixedTime := time.Date(2023, 10, 1, 12, 0, 0, 0, time.UTC)
	fixedTimeStr := fixedTime.Format(time.RFC3339)

	// Helper values for pointers
	tag := "v1.0.0"
	digest := "sha256:123456789abcdef"

	type args struct {
		results []schemas.AnalyzeResult
	}

	tests := map[string]struct {
		args args
		want [][]string // Expected structure (rows x columns)
	}{
		"should write header only when results are empty": {
			args: args{
				results: []schemas.AnalyzeResult{},
			},
			want: [][]string{
				{"Scan Time", "Host", "Project ID", "Repository ID", "Image Name", "Tag", "Digest", "Vulnerability ID", "Severity", "CVSS Score", "Package Type", "Package Name", "Installed Version", "Fixed Version", "Description", "Reference URL"},
			},
		},
		"should format standard vulnerability data correctly": {
			args: args{
				results: []schemas.AnalyzeResult{
					{
						Artifact: schemas.ArtifactReference{
							Host:         "asia.gcr.io",
							ProjectID:    "my-project",
							RepositoryID: "my-repo",
							ImageName:    "app",
							Tag:          &tag,
						},
						ScanTime: fixedTime,
						Vulnerabilities: []schemas.Vulnerability{
							{
								ID:               "CVE-2023-9999",
								Severity:         schemas.SeverityHigh,
								CVSSScore:        8.5,
								PackageName:      "openssl",
								InstalledVersion: "1.1.1",
								FixedVersion:     "1.1.2",
								Description:      "Buffer overflow",
								URLs:             []string{"https://cve.mitre.org/..."},
							},
						},
					},
				},
			},
			want: [][]string{
				{"Scan Time", "Host", "Project ID", "Repository ID", "Image Name", "Tag", "Digest", "Vulnerability ID", "Severity", "CVSS Score", "Package Type", "Package Name", "Installed Version", "Fixed Version", "Description", "Reference URL"},
				{
					fixedTimeStr,
					"asia.gcr.io",
					"my-project",
					"my-repo",
					"app",
					"v1.0.0",
					"",
					"CVE-2023-9999",
					"HIGH",
					"8.5",
					"",
					"openssl",
					"1.1.1",
					"1.1.2",
					"Buffer overflow",
					"https://cve.mitre.org/...",
				},
			},
		},
		"should handle multiple vulnerabilities (flattening)": {
			args: args{
				results: []schemas.AnalyzeResult{
					{
						Artifact: schemas.ArtifactReference{
							Host:         "gcr.io",
							ProjectID:    "p",
							RepositoryID: "r",
							ImageName:    "multi",
						},
						ScanTime: fixedTime,
						Vulnerabilities: []schemas.Vulnerability{
							{ID: "CVE-1", Severity: schemas.SeverityLow},
							{ID: "CVE-2", Severity: schemas.SeverityMedium},
						},
					},
				},
			},
			want: [][]string{
				{"Scan Time", "Host", "Project ID", "Repository ID", "Image Name", "Tag", "Digest", "Vulnerability ID", "Severity", "CVSS Score", "Package Type", "Package Name", "Installed Version", "Fixed Version", "Description", "Reference URL"},
				{fixedTimeStr, "gcr.io", "p", "r", "multi", "", "", "CVE-1", "LOW", "0.0", "", "", "", "", "", ""},
				{fixedTimeStr, "gcr.io", "p", "r", "multi", "", "", "CVE-2", "MEDIUM", "0.0", "", "", "", "", "", ""},
			},
		},
		"should handle special characters (CSV escaping)": {
			args: args{
				results: []schemas.AnalyzeResult{
					{
						Artifact: schemas.ArtifactReference{
							Host:         "pkg.dev",
							ProjectID:    "p",
							RepositoryID: "r",
							ImageName:    "esc",
							Digest:       &digest,
						},
						ScanTime: fixedTime,
						Vulnerabilities: []schemas.Vulnerability{
							{
								ID:          "CVE-ESC",
								Description: "Line 1\nLine 2, with \"quotes\"",
							},
						},
					},
				},
			},
			want: [][]string{
				{"Scan Time", "Host", "Project ID", "Repository ID", "Image Name", "Tag", "Digest", "Vulnerability ID", "Severity", "CVSS Score", "Package Type", "Package Name", "Installed Version", "Fixed Version", "Description", "Reference URL"},
				{
					fixedTimeStr,
					"pkg.dev",
					"p",
					"r",
					"esc",
					"",
					"sha256:123456789abcdef",
					"CVE-ESC",
					"",    // Unspecified severity
					"0.0", // Zero score
					"",    // Package Type
					"", "", "",
					"Line 1\nLine 2, with \"quotes\"", // CSV reader automatically handles unescaping
					"",
				},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			out := &bytes.Buffer{}
			e := exporter.NewCSVExporter(out)

			err := e.Export(context.Background(), tt.args.results)
			if err != nil {
				t.Fatalf("Export() error = %v", err)
			}

			// Verify structural equality using a CSV parser
			gotRecords := parseTable(t, out.Bytes(), ',')
			if diff := cmp.Diff(tt.want, gotRecords); diff != "" {
				t.Errorf("Export() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestTableExporter_Export_TSV verifies that the TSV configuration (tab delimiter) works correctly.
func TestTableExporter_Export_TSV(t *testing.T) {
	// Arrange
	fixedTime := time.Date(2023, 10, 1, 0, 0, 0, 0, time.UTC)
	fixedTimeStr := fixedTime.Format(time.RFC3339)

	results := []schemas.AnalyzeResult{
		{
			Artifact: schemas.ArtifactReference{
				Host: "h", ProjectID: "p", RepositoryID: "r", ImageName: "i",
			},
			ScanTime: fixedTime,
			Vulnerabilities: []schemas.Vulnerability{
				{ID: "CVE-TSV", Severity: schemas.SeverityCritical},
			},
		},
	}

	want := [][]string{
		{"Scan Time", "Host", "Project ID", "Repository ID", "Image Name", "Tag", "Digest", "Vulnerability ID", "Severity", "CVSS Score", "Package Type", "Package Name", "Installed Version", "Fixed Version", "Description", "Reference URL"},
		{fixedTimeStr, "h", "p", "r", "i", "", "", "CVE-TSV", "CRITICAL", "0.0", "", "", "", "", "", ""},
	}

	out := &bytes.Buffer{}
	e := exporter.NewTSVExporter(out)

	// Act
	err := e.Export(context.Background(), results)
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	// Assert
	gotRecords := parseTable(t, out.Bytes(), '\t')

	if diff := cmp.Diff(want, gotRecords); diff != "" {
		t.Errorf("Export() TSV mismatch (-want +got):\n%s", diff)
	}
}

// parseTable is a helper to read CSV/TSV bytes back into a 2D slice
func parseTable(t *testing.T, data []byte, comma rune) [][]string {
	t.Helper()
	r := csv.NewReader(bytes.NewReader(data))
	r.Comma = comma
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("failed to parse table output with comma='%c': %v", comma, err)
	}
	return records
}
