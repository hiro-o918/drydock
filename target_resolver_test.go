package drydock_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hiro-o918/drydock"
	"github.com/hiro-o918/drydock/schemas"
	"github.com/hiro-o918/drydock/utils"
)

func newTestTarget(imageName, digest string) drydock.ImageTarget {
	return drydock.ImageTarget{
		Artifact: schemas.ArtifactReference{
			Host:         "us-central1-docker.pkg.dev",
			ProjectID:    "my-project",
			RepositoryID: "my-repo",
			ImageName:    imageName,
			Digest:       utils.ToPtr(digest),
		},
		Location: "us-central1",
	}
}

// fakeTargetResolver is a hand-written fake used to test composition of
// TargetResolver implementations without mocking any external API.
type fakeTargetResolver struct {
	targets []drydock.ImageTarget
	err     error
}

func (f fakeTargetResolver) Resolve(_ context.Context) ([]drydock.ImageTarget, error) {
	return f.targets, f.err
}

func TestStaticResolver_Resolve(t *testing.T) {
	tests := map[string]struct {
		targets []drydock.ImageTarget
		want    []drydock.ImageTarget
	}{
		"should return the configured targets": {
			targets: []drydock.ImageTarget{newTestTarget("app-a", "sha:a"), newTestTarget("app-b", "sha:b")},
			want:    []drydock.ImageTarget{newTestTarget("app-a", "sha:a"), newTestTarget("app-b", "sha:b")},
		},
		"should return no targets when none are configured": {
			targets: nil,
			want:    nil,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			resolver := drydock.NewStaticResolver(tt.targets...)

			got, err := resolver.Resolve(context.Background())
			if err != nil {
				t.Fatalf("Resolve() unexpected error: %v", err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Resolve() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUnionResolver_Resolve(t *testing.T) {
	errA := errors.New("resolver a failed")

	tests := map[string]struct {
		resolvers []drydock.TargetResolver
		want      []drydock.ImageTarget
		wantErr   bool
	}{
		"should merge targets from all resolvers in order": {
			resolvers: []drydock.TargetResolver{
				fakeTargetResolver{targets: []drydock.ImageTarget{newTestTarget("app-a", "sha:a")}},
				fakeTargetResolver{targets: []drydock.ImageTarget{newTestTarget("app-b", "sha:b")}},
			},
			want: []drydock.ImageTarget{newTestTarget("app-a", "sha:a"), newTestTarget("app-b", "sha:b")},
		},
		"should drop duplicate digests keeping the first occurrence": {
			resolvers: []drydock.TargetResolver{
				fakeTargetResolver{targets: []drydock.ImageTarget{newTestTarget("app-a", "sha:dup")}},
				fakeTargetResolver{targets: []drydock.ImageTarget{newTestTarget("app-a-alias", "sha:dup"), newTestTarget("app-b", "sha:b")}},
			},
			want: []drydock.ImageTarget{newTestTarget("app-a", "sha:dup"), newTestTarget("app-b", "sha:b")},
		},
		"should return results from the remaining resolvers when one fails": {
			resolvers: []drydock.TargetResolver{
				fakeTargetResolver{err: errA},
				fakeTargetResolver{targets: []drydock.ImageTarget{newTestTarget("app-b", "sha:b")}},
			},
			want:    []drydock.ImageTarget{newTestTarget("app-b", "sha:b")},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			resolver := drydock.NewUnionResolver(tt.resolvers...)

			got, err := resolver.Resolve(context.Background())

			if (err != nil) != tt.wantErr {
				t.Fatalf("Resolve() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Resolve() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDedupTargets(t *testing.T) {
	tests := map[string]struct {
		targets []drydock.ImageTarget
		want    []drydock.ImageTarget
	}{
		"should keep all targets when digests are unique": {
			targets: []drydock.ImageTarget{newTestTarget("app-a", "sha:a"), newTestTarget("app-b", "sha:b")},
			want:    []drydock.ImageTarget{newTestTarget("app-a", "sha:a"), newTestTarget("app-b", "sha:b")},
		},
		"should drop later duplicates and preserve input order": {
			targets: []drydock.ImageTarget{
				newTestTarget("app-a", "sha:dup"),
				newTestTarget("app-b", "sha:b"),
				newTestTarget("app-a-alias", "sha:dup"),
			},
			want: []drydock.ImageTarget{newTestTarget("app-a", "sha:dup"), newTestTarget("app-b", "sha:b")},
		},
		"should return an empty slice when input is empty": {
			targets: []drydock.ImageTarget{},
			want:    []drydock.ImageTarget{},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := drydock.ExportDedupTargets(tt.targets)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("dedupTargets() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
