package main

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hiro-o918/drydock"
	"github.com/hiro-o918/drydock/schemas"
	"github.com/hiro-o918/drydock/utils"
)

func TestNewLatestDiscoveryConfig(t *testing.T) {
	tests := map[string]struct {
		cfg  *Config
		want latestDiscoveryConfig
	}{
		"should keep only the digest count when no filters are set": {
			cfg:  &Config{Latest: 1},
			want: latestDiscoveryConfig{count: 1},
		},
		"should carry over repository, exclude-repository, image-filter and max-age": {
			cfg: &Config{
				Latest:              3,
				Repositories:        []string{"repo-a", "repo-b"},
				ExcludeRepositories: []string{"repo-c"},
				ImageFilters:        []string{"service/*"},
				MaxAge:              24 * time.Hour,
			},
			want: latestDiscoveryConfig{
				count:               3,
				repositories:        []string{"repo-a", "repo-b"},
				excludeRepositories: []string{"repo-c"},
				imageFilters:        []string{"service/*"},
				maxAge:              24 * time.Hour,
			},
		},
		"should ignore a non-positive max-age": {
			cfg:  &Config{Latest: 1, MaxAge: 0},
			want: latestDiscoveryConfig{count: 1},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := newLatestDiscoveryConfig(tt.cfg)
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(latestDiscoveryConfig{})); diff != "" {
				t.Errorf("newLatestDiscoveryConfig() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// NOTE: this test asserts only the number of options built, not their
// effect, because drydock.LatestResolverOption values are closures and
// cannot be compared for equality. The resulting policy for an equivalent
// option set is covered by drydock's own TestNewLatestResolver_Policy;
// TestNewLatestDiscoveryConfig above covers the comparable part of this
// CLI-flag-to-policy mapping.
func TestLatestDiscoveryConfig_ToOptions(t *testing.T) {
	tests := map[string]struct {
		config latestDiscoveryConfig
		want   int
	}{
		"should build only the count option when no filters are set": {
			config: latestDiscoveryConfig{count: 2},
			want:   1,
		},
		"should build one option per filter when all are set": {
			config: latestDiscoveryConfig{
				count:               3,
				repositories:        []string{"repo-a"},
				excludeRepositories: []string{"repo-b"},
				imageFilters:        []string{"service/*"},
				maxAge:              time.Hour,
			},
			want: 5,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := len(tt.config.toOptions())
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("toOptions() option count mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBuildStaticTargets(t *testing.T) {
	tests := map[string]struct {
		digests  []string
		location string
		want     []drydock.ImageTarget
		wantErr  bool
	}{
		"should build one target per digest": {
			digests: []string{
				"us-central1-docker.pkg.dev/p/r/img@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				"us-central1-docker.pkg.dev/p/r/img2:v1",
			},
			location: "us-central1",
			want: []drydock.ImageTarget{
				{
					Artifact: schemas.ArtifactReference{
						Host:         "us-central1-docker.pkg.dev",
						ProjectID:    "p",
						RepositoryID: "r",
						ImageName:    "img",
						Digest:       utils.ToPtr("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
					},
					URI:      "us-central1-docker.pkg.dev/p/r/img@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					Location: "us-central1",
				},
				{
					Artifact: schemas.ArtifactReference{
						Host:         "us-central1-docker.pkg.dev",
						ProjectID:    "p",
						RepositoryID: "r",
						ImageName:    "img2",
						Tag:          utils.ToPtr("v1"),
					},
					URI:      "us-central1-docker.pkg.dev/p/r/img2:v1",
					Location: "us-central1",
				},
			},
		},
		"should return no targets for no digests": {
			digests:  nil,
			location: "us-central1",
			want:     []drydock.ImageTarget{},
		},
		"should return an error when a digest is not a valid image reference": {
			digests:  []string{"not-a-valid-reference"},
			location: "us-central1",
			wantErr:  true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := buildStaticTargets(tt.digests, tt.location)

			if (err != nil) != tt.wantErr {
				t.Fatalf("buildStaticTargets() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("buildStaticTargets() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestTargetResolverOption(t *testing.T) {
	tests := map[string]struct {
		cfg     *Config
		wantErr bool
	}{
		"should succeed when relying on default discovery": {
			cfg: &Config{Location: "us-central1", Latest: 1},
		},
		"should succeed when digest is a valid image reference": {
			cfg: &Config{
				Location: "us-central1",
				Latest:   1,
				Digests:  []string{"us-central1-docker.pkg.dev/p/r/img@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
			},
		},
		"should return an error when digest is not a valid image reference": {
			cfg: &Config{
				Location: "us-central1",
				Latest:   1,
				Digests:  []string{"not-a-valid-reference"},
			},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			opt, err := targetResolverOption(tt.cfg)

			if (err != nil) != tt.wantErr {
				t.Fatalf("targetResolverOption() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if opt != nil {
					t.Errorf("targetResolverOption() option = %v, want nil on error", opt)
				}
				return
			}
			if opt == nil {
				t.Error("targetResolverOption() option = nil, want a non-nil ScannerOption")
			}
		})
	}
}
