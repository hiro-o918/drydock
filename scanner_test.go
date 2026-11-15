package drydock_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hiro-o918/drydock"
)

func TestSameUnderlyingImageResolver(t *testing.T) {
	resolverA := &drydock.ImageResolver{}
	resolverB := &drydock.ImageResolver{}

	tests := map[string]struct {
		target   drydock.TargetResolver
		resolver *drydock.ImageResolver
		want     bool
	}{
		"should be true when target is a LatestResolver wrapping the same resolver": {
			target:   drydock.NewLatestResolver(resolverA, "my-project", "us-central1"),
			resolver: resolverA,
			want:     true,
		},
		"should be false when target is a LatestResolver wrapping a different resolver": {
			target:   drydock.NewLatestResolver(resolverA, "my-project", "us-central1"),
			resolver: resolverB,
			want:     false,
		},
		"should be false when target is not a LatestResolver": {
			target:   drydock.NewStaticResolver(),
			resolver: resolverA,
			want:     false,
		},
		"should be false when resolver is nil": {
			target:   drydock.NewLatestResolver(resolverA, "my-project", "us-central1"),
			resolver: nil,
			want:     false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := drydock.ExportSameUnderlyingImageResolver(tt.target, tt.resolver)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("sameUnderlyingImageResolver() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
