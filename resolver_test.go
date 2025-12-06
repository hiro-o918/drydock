package drydock_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hiro-o918/drydock"
)

func TestIsDigest(t *testing.T) {
	tests := map[string]struct {
		input string
		want  bool
	}{
		"should return true when tag starts with sha256 prefix": {
			input: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			want:  true,
		},
		"should return false when tag is a normal version tag": {
			input: "latest",
			want:  false,
		},
		"should return false when tag is empty": {
			input: "",
			want:  false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := drydock.ExportIsDigest(tt.input)
			if got != tt.want {
				t.Errorf("IsDigest(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseDigestFromURI(t *testing.T) {
	tests := map[string]struct {
		input   string
		want    string
		wantErr bool
	}{
		"should extract digest when uri format is valid": {
			input:   "us-central1-docker.pkg.dev/my-project/my-repo/my-image@sha256:123456789abcdef",
			want:    "sha256:123456789abcdef",
			wantErr: false,
		},
		"should fail when separator @ is missing": {
			input:   "us-central1-docker.pkg.dev/my-project/my-repo/my-image:latest",
			wantErr: true,
		},
		"should fail when digest part does not start with sha256:": {
			input:   "us-central1-docker.pkg.dev/my-project/my-repo/my-image@md5:12345",
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := drydock.ExportParseDigestFromURI(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDigestFromURI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("ParseDigestFromURI() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestSelectBestDigest(t *testing.T) {
	// Helper times for comparison
	now := time.Now()
	yesterday := now.Add(-24 * time.Hour)
	lastWeek := now.Add(-7 * 24 * time.Hour)

	tests := map[string]struct {
		candidates []drydock.ExportCandidateImage
		want       drydock.ExportCandidateImage
	}{
		"should prioritize 'latest' tag even if it is older than others": {
			// Case: 'latest' tag exists but is older than another tag. 'latest' should win.
			candidates: []drydock.ExportCandidateImage{
				{Digest: "sha:old-latest", Tags: []string{"latest", "v1"}, UpdateTime: yesterday},
				{Digest: "sha:new-beta", Tags: []string{"v2-beta"}, UpdateTime: now},
			},
			want: drydock.ExportCandidateImage{
				Digest: "sha:old-latest", Tags: []string{"latest", "v1"}, UpdateTime: yesterday,
			},
		},
		"should pick the newest timestamp when 'latest' tag is missing": {
			// Case: No 'latest' tag. Should pick the one with the most recent timestamp.
			candidates: []drydock.ExportCandidateImage{
				{Digest: "sha:old", Tags: []string{"v1"}, UpdateTime: lastWeek},
				{Digest: "sha:mid", Tags: []string{"v2"}, UpdateTime: yesterday},
				{Digest: "sha:new", Tags: []string{"v3"}, UpdateTime: now},
			},
			want: drydock.ExportCandidateImage{
				Digest: "sha:new", Tags: []string{"v3"}, UpdateTime: now,
			},
		},
		"should return single candidate if only one exists": {
			candidates: []drydock.ExportCandidateImage{
				{Digest: "sha:single", Tags: nil, UpdateTime: now},
			},
			want: drydock.ExportCandidateImage{
				Digest: "sha:single", Tags: nil, UpdateTime: now,
			},
		},
		"should return empty struct when input list is empty": {
			candidates: []drydock.ExportCandidateImage{},
			want:       drydock.ExportCandidateImage{},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := drydock.ExportSelectBestDigest(tt.candidates)

			// cmp.Diff handles deep comparison including time.Time
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("SelectBestDigest() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
