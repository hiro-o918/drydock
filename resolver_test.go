package drydock_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hiro-o918/drydock"
	"github.com/hiro-o918/drydock/schemas"
	"github.com/hiro-o918/drydock/utils"
)

func TestParseArtifactURI(t *testing.T) {
	const validHash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	tests := []struct {
		name    string
		input   string
		want    schemas.ArtifactReference
		wantErr bool
	}{
		{
			name:  "Valid URI with Digest",
			input: "us-central1-docker.pkg.dev/my-project/my-repo/my-image@" + validHash,
			want: schemas.ArtifactReference{
				Host:         "us-central1-docker.pkg.dev",
				ProjectID:    "my-project",
				RepositoryID: "my-repo",
				ImageName:    "my-image",
				Tag:          nil,
				Digest:       utils.ToPtr(validHash),
			},
			wantErr: false,
		},
		{
			name:  "Valid URI with Nested Namespace and Digest",
			input: "us-central1-docker.pkg.dev/my-project/my-repo/namespace/my-image@" + validHash,
			want: schemas.ArtifactReference{
				Host:         "us-central1-docker.pkg.dev",
				ProjectID:    "my-project",
				RepositoryID: "my-repo",
				ImageName:    "namespace/my-image",
				Tag:          nil,
				Digest:       utils.ToPtr(validHash),
			},
			wantErr: false,
		},
		{
			name:  "Valid URI with Tag only",
			input: "asia-northeast1-docker.pkg.dev/prod/docker/nginx:v1.2.3",
			want: schemas.ArtifactReference{
				Host:         "asia-northeast1-docker.pkg.dev",
				ProjectID:    "prod",
				RepositoryID: "docker",
				ImageName:    "nginx",
				Tag:          utils.ToPtr("v1.2.3"),
				Digest:       nil,
			},
			wantErr: false,
		},
		{
			name:  "Valid URI with Tag AND Digest (Pinning)",
			input: "asia-northeast1-docker.pkg.dev/prod/docker/nginx:latest@" + validHash,
			want: schemas.ArtifactReference{
				Host:         "asia-northeast1-docker.pkg.dev",
				ProjectID:    "prod",
				RepositoryID: "docker",
				ImageName:    "nginx",
				Tag:          utils.ToPtr("latest"),
				Digest:       utils.ToPtr(validHash),
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

func TestSelectDigests(t *testing.T) {
	// Helper times for comparison
	now := time.Now()
	yesterday := now.Add(-24 * time.Hour)
	lastWeek := now.Add(-7 * 24 * time.Hour)

	tests := map[string]struct {
		candidates []drydock.ExportCandidateImage
		opts       drydock.ExportDigestSelectionOptions
		want       []drydock.ExportCandidateImage
	}{
		"should prioritize preferred tag even if it is older than others": {
			candidates: []drydock.ExportCandidateImage{
				{Digest: "sha:old-latest", Tags: []string{"latest", "v1"}, UpdateTime: yesterday},
				{Digest: "sha:new-beta", Tags: []string{"v2-beta"}, UpdateTime: now},
			},
			opts: drydock.NewExportDigestSelectionOptions(1, "latest", 0, now),
			want: []drydock.ExportCandidateImage{
				{Digest: "sha:old-latest", Tags: []string{"latest", "v1"}, UpdateTime: yesterday},
			},
		},
		"should pick the newest timestamp when preferred tag is missing": {
			candidates: []drydock.ExportCandidateImage{
				{Digest: "sha:old", Tags: []string{"v1"}, UpdateTime: lastWeek},
				{Digest: "sha:mid", Tags: []string{"v2"}, UpdateTime: yesterday},
				{Digest: "sha:new", Tags: []string{"v3"}, UpdateTime: now},
			},
			opts: drydock.NewExportDigestSelectionOptions(1, "latest", 0, now),
			want: []drydock.ExportCandidateImage{
				{Digest: "sha:new", Tags: []string{"v3"}, UpdateTime: now},
			},
		},
		"should return single candidate if only one exists": {
			candidates: []drydock.ExportCandidateImage{
				{Digest: "sha:single", Tags: nil, UpdateTime: now},
			},
			opts: drydock.NewExportDigestSelectionOptions(1, "latest", 0, now),
			want: []drydock.ExportCandidateImage{
				{Digest: "sha:single", Tags: nil, UpdateTime: now},
			},
		},
		"should return no candidates when input list is empty": {
			candidates: []drydock.ExportCandidateImage{},
			opts:       drydock.NewExportDigestSelectionOptions(1, "latest", 0, now),
			want:       []drydock.ExportCandidateImage{},
		},
		"should keep the N most recent candidates when count is greater than one": {
			candidates: []drydock.ExportCandidateImage{
				{Digest: "sha:old", Tags: []string{"v1"}, UpdateTime: lastWeek},
				{Digest: "sha:mid", Tags: []string{"v2"}, UpdateTime: yesterday},
				{Digest: "sha:new", Tags: []string{"v3"}, UpdateTime: now},
			},
			opts: drydock.NewExportDigestSelectionOptions(2, "", 0, now),
			want: []drydock.ExportCandidateImage{
				{Digest: "sha:new", Tags: []string{"v3"}, UpdateTime: now},
				{Digest: "sha:mid", Tags: []string{"v2"}, UpdateTime: yesterday},
			},
		},
		"should drop candidates older than maxAge": {
			candidates: []drydock.ExportCandidateImage{
				{Digest: "sha:old", Tags: []string{"v1"}, UpdateTime: lastWeek},
				{Digest: "sha:new", Tags: []string{"v3"}, UpdateTime: now},
			},
			opts: drydock.NewExportDigestSelectionOptions(10, "", 24*time.Hour, now),
			want: []drydock.ExportCandidateImage{
				{Digest: "sha:new", Tags: []string{"v3"}, UpdateTime: now},
			},
		},
		"should return no candidates when all are older than maxAge": {
			candidates: []drydock.ExportCandidateImage{
				{Digest: "sha:old", Tags: []string{"v1"}, UpdateTime: lastWeek},
			},
			opts: drydock.NewExportDigestSelectionOptions(10, "", time.Hour, now),
			want: []drydock.ExportCandidateImage{},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := drydock.ExportSelectDigests(tt.candidates, tt.opts)

			// cmp.Diff handles deep comparison including time.Time
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("selectDigests() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRepositoryAllowed(t *testing.T) {
	tests := map[string]struct {
		repositoryID string
		include      map[string]struct{}
		exclude      map[string]struct{}
		want         bool
	}{
		"should allow any repository when no filters are set": {
			repositoryID: "my-repo",
			want:         true,
		},
		"should allow a repository that is in the include set": {
			repositoryID: "my-repo",
			include:      map[string]struct{}{"my-repo": {}},
			want:         true,
		},
		"should reject a repository that is not in the include set": {
			repositoryID: "other-repo",
			include:      map[string]struct{}{"my-repo": {}},
			want:         false,
		},
		"should reject a repository that is in the exclude set": {
			repositoryID: "my-repo",
			exclude:      map[string]struct{}{"my-repo": {}},
			want:         false,
		},
		"should reject a repository excluded even if it is also included": {
			repositoryID: "my-repo",
			include:      map[string]struct{}{"my-repo": {}},
			exclude:      map[string]struct{}{"my-repo": {}},
			want:         false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := drydock.ExportRepositoryAllowed(tt.repositoryID, tt.include, tt.exclude)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("repositoryAllowed() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMatchesAnyImagePattern(t *testing.T) {
	tests := map[string]struct {
		imageName string
		patterns  []string
		want      bool
	}{
		"should match any image when no patterns are set": {
			imageName: "service/worker",
			want:      true,
		},
		"should match an exact pattern": {
			imageName: "worker",
			patterns:  []string{"worker"},
			want:      true,
		},
		"should match a glob prefix pattern": {
			imageName: "service/worker",
			patterns:  []string{"service/*"},
			want:      true,
		},
		"should match when any of several patterns matches": {
			imageName: "service/worker",
			patterns:  []string{"other/*", "service/*"},
			want:      true,
		},
		"should not match when no pattern matches": {
			imageName: "service/worker",
			patterns:  []string{"other/*"},
			want:      false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := drydock.ExportMatchesAnyImagePattern(tt.imageName, tt.patterns)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("matchesAnyImagePattern() mismatch (-want +got):\n%s", diff)
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
