package drydock

import (
	"context"
	"errors"
	"time"
)

// LatestResolver is a TargetResolver that discovers scan targets from
// Artifact Registry, selecting the most relevant digest(s) per image.
type LatestResolver struct {
	imageResolver *ImageResolver
	projectID     string
	location      string
	policy        scanPolicy
	now           func() time.Time
}

// LatestResolverOption configures a LatestResolver.
type LatestResolverOption func(*LatestResolver)

// NewLatestResolver creates a LatestResolver that scans projectID/location
// through imageResolver. By default it keeps one digest per image,
// preferring the "latest" tag when present, matching the historical
// AllLatestImages behavior.
func NewLatestResolver(imageResolver *ImageResolver, projectID, location string, opts ...LatestResolverOption) *LatestResolver {
	r := &LatestResolver{
		imageResolver: imageResolver,
		projectID:     projectID,
		location:      location,
		policy:        defaultScanPolicy(),
		now:           time.Now,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// WithLatestCount sets how many of the most relevant digests to keep per image.
func WithLatestCount(n int) LatestResolverOption {
	return func(r *LatestResolver) {
		r.policy.selection.count = n
		if n > r.policy.maxCandidates {
			r.policy.maxCandidates = n
		}
	}
}

// WithPreferTag sets the tag that is always ranked ahead of other candidates
// when present. Pass "" to disable tag preference and rank purely by recency.
func WithPreferTag(tag string) LatestResolverOption {
	return func(r *LatestResolver) {
		r.policy.selection.preferTag = tag
	}
}

// WithRepositories restricts discovery to the given repository IDs.
func WithRepositories(repositoryIDs ...string) LatestResolverOption {
	return func(r *LatestResolver) {
		r.policy.includeRepositories = toSet(repositoryIDs)
	}
}

// WithExcludeRepositories excludes the given repository IDs from discovery.
func WithExcludeRepositories(repositoryIDs ...string) LatestResolverOption {
	return func(r *LatestResolver) {
		r.policy.excludeRepositories = toSet(repositoryIDs)
	}
}

// WithImageFilter restricts discovery to images whose name matches at least
// one of the given glob patterns (see path.Match).
func WithImageFilter(patterns ...string) LatestResolverOption {
	return func(r *LatestResolver) {
		r.policy.imagePatterns = patterns
	}
}

// WithMaxAge excludes digests whose last update time is older than d.
func WithMaxAge(d time.Duration) LatestResolverOption {
	return func(r *LatestResolver) {
		r.policy.selection.maxAge = d
	}
}

// Resolve implements TargetResolver by scanning all Docker repositories
// under the configured project and location.
func (r *LatestResolver) Resolve(ctx context.Context) ([]ImageTarget, error) {
	policy := r.policy
	policy.selection.now = r.now()

	var targets []ImageTarget
	var errs error
	for target, err := range r.imageResolver.discoverImages(ctx, r.projectID, r.location, policy) {
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		targets = append(targets, target)
	}
	return targets, errs
}

func toSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	return set
}
