package drydock_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hiro-o918/drydock"
)

func TestNewLatestResolver_Policy(t *testing.T) {
	tests := map[string]struct {
		opts []drydock.LatestResolverOption
		want drydock.ExportScanPolicy
	}{
		"should default to one digest per image preferring the latest tag": {
			opts: nil,
			want: drydock.NewExportScanPolicy(
				drydock.NewExportDigestSelectionOptions(1, "latest", 0, time.Time{}),
				drydock.MaxCandidates, nil, nil, nil,
			),
		},
		"should set the digest count and raise maxCandidates to match": {
			opts: []drydock.LatestResolverOption{drydock.WithLatestCount(10)},
			want: drydock.NewExportScanPolicy(
				drydock.NewExportDigestSelectionOptions(10, "latest", 0, time.Time{}),
				10, nil, nil, nil,
			),
		},
		"should clamp a non-positive digest count to one": {
			opts: []drydock.LatestResolverOption{drydock.WithLatestCount(0)},
			want: drydock.NewExportScanPolicy(
				drydock.NewExportDigestSelectionOptions(1, "latest", 0, time.Time{}),
				drydock.MaxCandidates, nil, nil, nil,
			),
		},
		"should not raise maxCandidates when the count is below it": {
			opts: []drydock.LatestResolverOption{drydock.WithLatestCount(2)},
			want: drydock.NewExportScanPolicy(
				drydock.NewExportDigestSelectionOptions(2, "latest", 0, time.Time{}),
				drydock.MaxCandidates, nil, nil, nil,
			),
		},
		"should set the preferred tag": {
			opts: []drydock.LatestResolverOption{drydock.WithPreferTag("stable")},
			want: drydock.NewExportScanPolicy(
				drydock.NewExportDigestSelectionOptions(1, "stable", 0, time.Time{}),
				drydock.MaxCandidates, nil, nil, nil,
			),
		},
		"should disable tag preference when given an empty tag": {
			opts: []drydock.LatestResolverOption{drydock.WithPreferTag("")},
			want: drydock.NewExportScanPolicy(
				drydock.NewExportDigestSelectionOptions(1, "", 0, time.Time{}),
				drydock.MaxCandidates, nil, nil, nil,
			),
		},
		"should restrict discovery to the given repositories": {
			opts: []drydock.LatestResolverOption{drydock.WithRepositories("repo-a", "repo-b")},
			want: drydock.NewExportScanPolicy(
				drydock.NewExportDigestSelectionOptions(1, "latest", 0, time.Time{}),
				drydock.MaxCandidates,
				map[string]struct{}{"repo-a": {}, "repo-b": {}},
				nil,
				nil,
			),
		},
		"should exclude the given repositories": {
			opts: []drydock.LatestResolverOption{drydock.WithExcludeRepositories("repo-c")},
			want: drydock.NewExportScanPolicy(
				drydock.NewExportDigestSelectionOptions(1, "latest", 0, time.Time{}),
				drydock.MaxCandidates,
				nil,
				map[string]struct{}{"repo-c": {}},
				nil,
			),
		},
		"should restrict discovery to images matching the given glob patterns": {
			opts: []drydock.LatestResolverOption{drydock.WithImageFilter("service/*", "worker")},
			want: drydock.NewExportScanPolicy(
				drydock.NewExportDigestSelectionOptions(1, "latest", 0, time.Time{}),
				drydock.MaxCandidates, nil, nil,
				[]string{"service/*", "worker"},
			),
		},
		"should set the max age": {
			opts: []drydock.LatestResolverOption{drydock.WithMaxAge(24 * time.Hour)},
			want: drydock.NewExportScanPolicy(
				drydock.NewExportDigestSelectionOptions(1, "latest", 24*time.Hour, time.Time{}),
				drydock.MaxCandidates, nil, nil, nil,
			),
		},
		"should apply multiple options together": {
			opts: []drydock.LatestResolverOption{
				drydock.WithLatestCount(3),
				drydock.WithPreferTag("stable"),
				drydock.WithRepositories("repo-a"),
				drydock.WithMaxAge(time.Hour),
			},
			want: drydock.NewExportScanPolicy(
				drydock.NewExportDigestSelectionOptions(3, "stable", time.Hour, time.Time{}),
				drydock.MaxCandidates,
				map[string]struct{}{"repo-a": {}},
				nil,
				nil,
			),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			resolver := drydock.NewLatestResolver(nil, "my-project", "us-central1", tt.opts...)

			got := drydock.ExportLatestResolverPolicy(resolver)

			diffOpts := cmp.AllowUnexported(drydock.ExportScanPolicy{}, drydock.ExportDigestSelectionOptions{})
			if diff := cmp.Diff(tt.want, got, diffOpts); diff != "" {
				t.Errorf("NewLatestResolver() policy mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
