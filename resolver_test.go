package drydock_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hiro-o918/drydock"
)

func TestParseArtifactURI(t *testing.T) {
	const validHash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	tests := []struct {
		name    string
		input   string
		want    drydock.ArtifactReference
		wantErr bool
	}{
		{
			name:  "Valid URI with Digest",
			input: "us-central1-docker.pkg.dev/my-project/my-repo/my-image@" + validHash,
			want: drydock.ArtifactReference{
				Host:         "us-central1-docker.pkg.dev",
				ProjectID:    "my-project",
				RepositoryID: "my-repo",
				ImageName:    "my-image",
				Tag:          nil,
				Digest:       drydock.ToPtr(validHash),
			},
			wantErr: false,
		},
		{
			name:  "Valid URI with Nested Namespace and Digest",
			input: "us-central1-docker.pkg.dev/my-project/my-repo/namespace/my-image@" + validHash,
			want: drydock.ArtifactReference{
				Host:         "us-central1-docker.pkg.dev",
				ProjectID:    "my-project",
				RepositoryID: "my-repo",
				ImageName:    "namespace/my-image",
				Tag:          nil,
				Digest:       drydock.ToPtr(validHash),
			},
			wantErr: false,
		},
		{
			name:  "Valid URI with Tag only",
			input: "asia-northeast1-docker.pkg.dev/prod/docker/nginx:v1.2.3",
			want: drydock.ArtifactReference{
				Host:         "asia-northeast1-docker.pkg.dev",
				ProjectID:    "prod",
				RepositoryID: "docker",
				ImageName:    "nginx",
				Tag:          drydock.ToPtr("v1.2.3"),
				Digest:       nil,
			},
			wantErr: false,
		},
		{
			name:  "Valid URI with Tag AND Digest (Pinning)",
			input: "asia-northeast1-docker.pkg.dev/prod/docker/nginx:latest@" + validHash,
			want: drydock.ArtifactReference{
				Host:         "asia-northeast1-docker.pkg.dev",
				ProjectID:    "prod",
				RepositoryID: "docker",
				ImageName:    "nginx",
				Tag:          drydock.ToPtr("latest"),
				Digest:       drydock.ToPtr(validHash),
			},
			wantErr: false,
		},
		{
			name:    "Fail: Insufficient path segments",
			input:   "us-central1-docker.pkg.dev/project@" + validHash,
			wantErr: true,
		},
		{
			name:    "Fail: Invalid digest prefix (md5)",
			input:   "us-central1-docker.pkg.dev/my-project/my-repo/my-image@md5:12345",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := drydock.ParseArtifactURI(tt.input)

			// Check error expectation
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseArtifactURI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check diff using go-cmp
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ParseArtifactURI() mismatch (-want +got):\n%s", diff)
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
			got := drydock.ExportSelectBestDigest("test-image", "us-central1", "test-repo", tt.candidates)

			// cmp.Diff handles deep comparison including time.Time
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("SelectBestDigest() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExtractLocationAndRepository(t *testing.T) {
	tests := map[string]struct {
		input        string
		wantLocation string
		wantRepo     string
	}{
		"should extract location and repository when repo name format is valid": {
			input:        "projects/my-project/locations/us-central1/repositories/my-repo",
			wantLocation: "us-central1",
			wantRepo:     "my-repo",
		},
		"should handle asia-northeast1 location": {
			input:        "projects/test/locations/asia-northeast1/repositories/test-repo",
			wantLocation: "asia-northeast1",
			wantRepo:     "test-repo",
		},
		"should return empty strings when format is invalid": {
			input:        "invalid",
			wantLocation: "",
			wantRepo:     "",
		},
		"should return empty strings when parts are insufficient": {
			input:        "projects/my-project/locations/us-central1",
			wantLocation: "",
			wantRepo:     "",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			gotLocation, gotRepo := drydock.ExportExtractLocationAndRepository(tt.input)
			if gotLocation != tt.wantLocation {
				t.Errorf("ExtractLocationAndRepository() location = %v, want %v", gotLocation, tt.wantLocation)
			}
			if gotRepo != tt.wantRepo {
				t.Errorf("ExtractLocationAndRepository() repo = %v, want %v", gotRepo, tt.wantRepo)
			}
		})
	}
}
