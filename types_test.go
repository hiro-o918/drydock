package drydock_test

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hiro-o918/drydock"
)

func TestArtifactReference_ToResourceURL(t *testing.T) {
	tests := map[string]struct {
		artifact ArtifactReference
		location string
		want     string
	}{
		"should generate correct resource URL with digest": {
			artifact: ArtifactReference{
				Host:         "us-central1-docker.pkg.dev",
				ProjectID:    "my-project",
				RepositoryID: "my-repo",
				ImageName:    "my-image",
				Digest:       drydock.ToPtr("sha256:abc123"),
			},
			location: "us-central1",
			want:     "https://us-central1-docker.pkg.dev/my-project/my-repo/my-image@sha256:abc123",
		},
		"should handle nil digest": {
			artifact: ArtifactReference{
				Host:         "asia-northeast1-docker.pkg.dev",
				ProjectID:    "test-project",
				RepositoryID: "test-repo",
				ImageName:    "test-image",
				Digest:       nil,
			},
			location: "asia-northeast1",
			want:     "https://asia-northeast1-docker.pkg.dev/test-project/test-repo/test-image@",
		},
		"should handle nested image name": {
			artifact: ArtifactReference{
				Host:         "us-central1-docker.pkg.dev",
				ProjectID:    "my-project",
				RepositoryID: "my-repo",
				ImageName:    "namespace/my-image",
				Digest:       drydock.ToPtr("sha256:def456"),
			},
			location: "us-central1",
			want:     "https://us-central1-docker.pkg.dev/my-project/my-repo/namespace/my-image@sha256:def456",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := tt.artifact.ToResourceURL(tt.location)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ToResourceURL() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestArtifactReference_String(t *testing.T) {
	tests := map[string]struct {
		artifact ArtifactReference
		want     string
	}{
		"should format with digest only": {
			artifact: ArtifactReference{
				Host:         "us-central1-docker.pkg.dev",
				ProjectID:    "my-project",
				RepositoryID: "my-repo",
				ImageName:    "my-image",
				Digest:       drydock.ToPtr("sha256:abc123"),
			},
			want: "us-central1-docker.pkg.dev/my-project/my-repo/my-image@sha256:abc123",
		},
		"should format with tag only": {
			artifact: ArtifactReference{
				Host:         "us-central1-docker.pkg.dev",
				ProjectID:    "my-project",
				RepositoryID: "my-repo",
				ImageName:    "my-image",
				Tag:          drydock.ToPtr("latest"),
			},
			want: "us-central1-docker.pkg.dev/my-project/my-repo/my-image:latest",
		},
		"should format with tag and digest": {
			artifact: ArtifactReference{
				Host:         "us-central1-docker.pkg.dev",
				ProjectID:    "my-project",
				RepositoryID: "my-repo",
				ImageName:    "my-image",
				Tag:          drydock.ToPtr("v1.0.0"),
				Digest:       drydock.ToPtr("sha256:abc123"),
			},
			want: "us-central1-docker.pkg.dev/my-project/my-repo/my-image:v1.0.0@sha256:abc123",
		},
		"should format with neither tag nor digest": {
			artifact: ArtifactReference{
				Host:         "us-central1-docker.pkg.dev",
				ProjectID:    "my-project",
				RepositoryID: "my-repo",
				ImageName:    "my-image",
			},
			want: "us-central1-docker.pkg.dev/my-project/my-repo/my-image",
		},
		"should handle nested image name": {
			artifact: ArtifactReference{
				Host:         "asia-northeast1-docker.pkg.dev",
				ProjectID:    "test-project",
				RepositoryID: "test-repo",
				ImageName:    "namespace/service/worker",
				Tag:          drydock.ToPtr("prod"),
			},
			want: "asia-northeast1-docker.pkg.dev/test-project/test-repo/namespace/service/worker:prod",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := tt.artifact.String()
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("String() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestArtifactReference_MarshalJSON(t *testing.T) {
	tests := map[string]struct {
		artifact ArtifactReference
		want     string
	}{
		"should include uri field in JSON": {
			artifact: ArtifactReference{
				Host:         "us-central1-docker.pkg.dev",
				ProjectID:    "my-project",
				RepositoryID: "my-repo",
				ImageName:    "my-image",
				Digest:       drydock.ToPtr("sha256:abc123"),
			},
			want: `{"host":"us-central1-docker.pkg.dev","projectID":"my-project","repositoryID":"my-repo","imageName":"my-image","digest":"sha256:abc123","uri":"us-central1-docker.pkg.dev/my-project/my-repo/my-image@sha256:abc123"}`,
		},
		"should omit nil tag and digest": {
			artifact: ArtifactReference{
				Host:         "us-central1-docker.pkg.dev",
				ProjectID:    "my-project",
				RepositoryID: "my-repo",
				ImageName:    "my-image",
			},
			want: `{"host":"us-central1-docker.pkg.dev","projectID":"my-project","repositoryID":"my-repo","imageName":"my-image","uri":"us-central1-docker.pkg.dev/my-project/my-repo/my-image"}`,
		},
		"should include tag when present": {
			artifact: ArtifactReference{
				Host:         "us-central1-docker.pkg.dev",
				ProjectID:    "my-project",
				RepositoryID: "my-repo",
				ImageName:    "my-image",
				Tag:          drydock.ToPtr("latest"),
				Digest:       drydock.ToPtr("sha256:abc123"),
			},
			want: `{"host":"us-central1-docker.pkg.dev","projectID":"my-project","repositoryID":"my-repo","imageName":"my-image","tag":"latest","digest":"sha256:abc123","uri":"us-central1-docker.pkg.dev/my-project/my-repo/my-image:latest@sha256:abc123"}`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := json.Marshal(tt.artifact)
			if err != nil {
				t.Fatalf("MarshalJSON() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, string(got)); diff != "" {
				t.Errorf("MarshalJSON() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestArtifactReference_StringRoundTrip tests the round-trip between String() and ParseArtifactURI().
// Note: ParseArtifactURI currently supports cases with both Tag and Digest,
// so we test cases with only Tag or only Digest.
func TestArtifactReference_StringRoundTrip(t *testing.T) {
	tests := map[string]struct {
		artifact drydock.ArtifactReference
	}{
		"should round-trip with digest only": {
			artifact: drydock.ArtifactReference{
				Host:         "us-central1-docker.pkg.dev",
				ProjectID:    "my-project",
				RepositoryID: "my-repo",
				ImageName:    "my-image",
				Digest:       drydock.ToPtr("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			},
		},
		"should round-trip with tag only": {
			artifact: drydock.ArtifactReference{
				Host:         "asia-northeast1-docker.pkg.dev",
				ProjectID:    "test-project",
				RepositoryID: "test-repo",
				ImageName:    "nginx",
				Tag:          drydock.ToPtr("latest"),
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			uri := tt.artifact.String()
			parsed, err := drydock.ParseArtifactURI(uri)
			if err != nil {
				t.Fatalf("ParseArtifactURI() error = %v", err)
			}
			if diff := cmp.Diff(tt.artifact, parsed); diff != "" {
				t.Errorf("Round-trip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Type alias for test readability
type ArtifactReference = drydock.ArtifactReference
