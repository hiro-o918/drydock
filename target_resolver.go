package drydock

import (
	"context"
	"errors"
	"slices"
)

// TargetResolver discovers the set of ImageTarget to scan.
type TargetResolver interface {
	// Resolve returns the targets to scan.
	Resolve(ctx context.Context) ([]ImageTarget, error)
}

// StaticResolver is a TargetResolver that always resolves to a fixed,
// pre-determined set of targets, bypassing discovery entirely.
type StaticResolver struct {
	targets []ImageTarget
}

// NewStaticResolver returns a TargetResolver that always resolves to the given targets.
func NewStaticResolver(targets ...ImageTarget) *StaticResolver {
	normalized := make([]ImageTarget, len(targets))
	copy(normalized, targets)
	return &StaticResolver{targets: normalized}
}

// Resolve implements TargetResolver.
func (r *StaticResolver) Resolve(_ context.Context) ([]ImageTarget, error) {
	return slices.Clone(r.targets), nil
}

// UnionResolver is a TargetResolver that merges the results of multiple
// resolvers, removing duplicate digests. The order of resolvers determines
// both the output order and which duplicate is kept.
type UnionResolver struct {
	resolvers []TargetResolver
}

// NewUnionResolver returns a TargetResolver that merges the results of the given resolvers.
func NewUnionResolver(resolvers ...TargetResolver) *UnionResolver {
	return &UnionResolver{resolvers: slices.Clone(resolvers)}
}

// Resolve implements TargetResolver. A resolver that fails does not prevent
// the results of the other resolvers from being returned; its error is
// joined into the returned error instead.
func (r *UnionResolver) Resolve(ctx context.Context) ([]ImageTarget, error) {
	var all []ImageTarget
	var errs error
	for _, resolver := range r.resolvers {
		targets, err := resolver.Resolve(ctx)
		if err != nil {
			errs = errors.Join(errs, err)
		}
		all = append(all, targets...)
	}
	return dedupTargets(all), errs
}

func targetDigestKey(t ImageTarget) string {
	if t.Artifact.Digest != nil {
		return *t.Artifact.Digest
	}
	return t.Artifact.String()
}

func dedupTargets(targets []ImageTarget) []ImageTarget {
	seen := make(map[string]struct{}, len(targets))
	result := make([]ImageTarget, 0, len(targets))
	for _, t := range targets {
		key := targetDigestKey(t)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, t)
	}
	return result
}
