package main

import (
	"testing"

	"github.com/hiro-o918/drydock"
)

func TestParseSeverity(t *testing.T) {
	tests := map[string]struct {
		input   string
		want    drydock.Severity
		wantErr bool
	}{
		"should parse MINIMAL severity": {
			input: "MINIMAL",
			want:  drydock.SeverityMinimal,
		},
		"should parse LOW severity": {
			input: "LOW",
			want:  drydock.SeverityLow,
		},
		"should parse MEDIUM severity": {
			input: "MEDIUM",
			want:  drydock.SeverityMedium,
		},
		"should parse HIGH severity": {
			input: "HIGH",
			want:  drydock.SeverityHigh,
		},
		"should parse CRITICAL severity": {
			input: "CRITICAL",
			want:  drydock.SeverityCritical,
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
