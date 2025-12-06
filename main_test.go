package main_test

import (
	"testing"

	"github.com/hiro-o918/drydock"
)

// ============================================================================
// Severity Tests
// ============================================================================

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		name     string
		severity main.Severity
		want     string
	}{
		{
			name:     "unspecified severity",
			severity: main.SeverityUnspecified,
			want:     "UNSPECIFIED",
		},
		{
			name:     "minimal severity",
			severity: main.SeverityMinimal,
			want:     "MINIMAL",
		},
		{
			name:     "low severity",
			severity: main.SeverityLow,
			want:     "LOW",
		},
		{
			name:     "medium severity",
			severity: main.SeverityMedium,
			want:     "MEDIUM",
		},
		{
			name:     "high severity",
			severity: main.SeverityHigh,
			want:     "HIGH",
		},
		{
			name:     "critical severity",
			severity: main.SeverityCritical,
			want:     "CRITICAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.severity); got != tt.want {
				t.Errorf("Severity = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// Domain Types Tests
// ============================================================================

func TestVulnerability(t *testing.T) {
	v := main.Vulnerability{
		ID:               "CVE-2024-1234",
		Severity:         main.SeverityHigh,
		PackageName:      "openssl",
		InstalledVersion: "1.0.0",
		FixedVersion:     "1.0.1",
		Description:      "Test vulnerability",
		CVSSScore:        7.5,
		URLs:             []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234"},
	}

	if v.ID != "CVE-2024-1234" {
		t.Errorf("Vulnerability.ID = %v, want CVE-2024-1234", v.ID)
	}
	if v.Severity != main.SeverityHigh {
		t.Errorf("Vulnerability.Severity = %v, want %v", v.Severity, main.SeverityHigh)
	}
	if v.CVSSScore != 7.5 {
		t.Errorf("Vulnerability.CVSSScore = %v, want 7.5", v.CVSSScore)
	}
}

func TestVulnerabilitySummary(t *testing.T) {
	summary := main.VulnerabilitySummary{
		TotalCount: 10,
		CountBySeverity: map[main.Severity]int{
			main.SeverityCritical: 2,
			main.SeverityHigh:     3,
			main.SeverityMedium:   3,
			main.SeverityLow:      2,
		},
		FixableCount: 7,
	}

	if summary.TotalCount != 10 {
		t.Errorf("VulnerabilitySummary.TotalCount = %v, want 10", summary.TotalCount)
	}
	if summary.FixableCount != 7 {
		t.Errorf("VulnerabilitySummary.FixableCount = %v, want 7", summary.FixableCount)
	}
	if summary.CountBySeverity[main.SeverityCritical] != 2 {
		t.Errorf("VulnerabilitySummary.CountBySeverity[Critical] = %v, want 2", summary.CountBySeverity[main.SeverityCritical])
	}
}
