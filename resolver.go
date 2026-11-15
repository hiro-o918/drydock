package drydock

import (
	"context"
	"fmt"
	"iter"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	artifactregistry "cloud.google.com/go/artifactregistry/apiv1"
	"cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb"
	"github.com/hiro-o918/drydock/schemas"
	"github.com/hiro-o918/drydock/utils"
	"github.com/rs/zerolog/log"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

const (
	// MaxCandidates is the number of latest digests to consider per image during discovery.
	// Limiting this prevents scanning thousands of old tags, significantly improving performance.
	MaxCandidates = 5
)

// ImageResolver handles resolving Docker image tags to SHA256 digests.
type ImageResolver struct {
	client *artifactregistry.Client
}

// ImageTarget represents a resolved target for scanning.
type ImageTarget struct {
	Artifact schemas.ArtifactReference // Structured image reference
	URI      string                    // Original API response URI (for debugging)
	Location string                    // GCP location (e.g., "us-central1")
}

// candidateImage is an internal struct used for selection logic.
type candidateImage struct {
	Digest     string
	Tags       []string
	UpdateTime time.Time
	URI        string
}

// NewImageResolver creates a new resolver with ADC authentication.
func NewImageResolver(ctx context.Context, opts ...option.ClientOption) (*ImageResolver, error) {
	client, err := artifactregistry.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Artifact Registry client: %w", err)
	}
	return &ImageResolver{client: client}, nil
}

// Close closes the underlying API client.
func (r *ImageResolver) Close() error {
	return r.client.Close()
}

// AllLatestImages returns an iterator that yields resolved image targets one by one.
// It scans all Docker repositories in the specified project and location.
// For each image found, it selects the best digest (preferring "latest" tag, otherwise newest).
func (r *ImageResolver) AllLatestImages(ctx context.Context, projectID, location string) iter.Seq2[ImageTarget, error] {
	return r.discoverImages(ctx, projectID, location, defaultScanPolicy())
}

// digestSelectionOptions configures how candidate digests are narrowed down
// to the ones that should be scanned for a single image.
type digestSelectionOptions struct {
	count     int
	preferTag string
	maxAge    time.Duration
	now       time.Time
}

// selectDigests narrows candidates down to at most opts.count entries,
// ranking a candidate tagged with opts.preferTag ahead of the rest and
// breaking remaining ties by recency, after dropping candidates older than
// opts.maxAge (when set). Input order is not relied upon.
func selectDigests(candidates []candidateImage, opts digestSelectionOptions) []candidateImage {
	filtered := candidates
	if opts.maxAge > 0 {
		filtered = make([]candidateImage, 0, len(candidates))
		for _, c := range candidates {
			if opts.now.Sub(c.UpdateTime) <= opts.maxAge {
				filtered = append(filtered, c)
			}
		}
	}

	sorted := slices.Clone(filtered)
	slices.SortStableFunc(sorted, func(a, b candidateImage) int {
		aPreferred := opts.preferTag != "" && slices.Contains(a.Tags, opts.preferTag)
		bPreferred := opts.preferTag != "" && slices.Contains(b.Tags, opts.preferTag)
		if aPreferred != bPreferred {
			if aPreferred {
				return -1
			}
			return 1
		}
		return b.UpdateTime.Compare(a.UpdateTime)
	})

	count := opts.count
	if count <= 0 || count > len(sorted) {
		count = len(sorted)
	}
	return sorted[:count]
}

// scanPolicy configures target discovery across repositories and images.
type scanPolicy struct {
	selection           digestSelectionOptions
	maxCandidates       int
	includeRepositories map[string]struct{}
	excludeRepositories map[string]struct{}
	imagePatterns       []string
}

// defaultScanPolicy reproduces the historical AllLatestImages behavior: one
// digest per image, preferring the "latest" tag, no filtering.
func defaultScanPolicy() scanPolicy {
	return scanPolicy{
		selection:     digestSelectionOptions{count: 1, preferTag: "latest"},
		maxCandidates: MaxCandidates,
	}
}

func repositoryAllowed(repositoryID string, include, exclude map[string]struct{}) bool {
	if len(include) > 0 {
		if _, ok := include[repositoryID]; !ok {
			return false
		}
	}
	_, excluded := exclude[repositoryID]
	return !excluded
}

// sortedImageNames avoids depending on Go's randomized map iteration order.
func sortedImageNames(grouped map[string][]candidateImage) []string {
	names := make([]string, 0, len(grouped))
	for name := range grouped {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func matchesAnyImagePattern(imageName string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if ok, err := path.Match(pattern, imageName); err == nil && ok {
			return true
		}
	}
	return false
}

// discoverImages is the generalized form of AllLatestImages, applying policy
// to decide which repositories, images and digests to yield.
func (r *ImageResolver) discoverImages(ctx context.Context, projectID, location string, policy scanPolicy) iter.Seq2[ImageTarget, error] {
	return func(yield func(ImageTarget, error) bool) {
		parent := fmt.Sprintf("projects/%s/locations/%s", projectID, location)
		repoReq := &artifactregistrypb.ListRepositoriesRequest{Parent: parent}
		repoIt := r.client.ListRepositories(ctx, repoReq)

		for {
			// 1. Fetch next repository
			repo, err := repoIt.Next()
			if err == iterator.Done {
				return // All repositories scanned
			}
			if err != nil {
				// Yield error. If caller stops, we return.
				if !yield(ImageTarget{}, fmt.Errorf("failed to list repositories: %w", err)) {
					return
				}
				// If error occurs, we stop iteration to be safe.
				return
			}

			// Filter: Only process Docker repositories
			if repo.Format != artifactregistrypb.Repository_DOCKER {
				continue
			}

			_, repositoryID := extractLocationAndRepository(repo.Name)
			if !repositoryAllowed(repositoryID, policy.includeRepositories, policy.excludeRepositories) {
				continue
			}

			// 2. Scan the repository for targets
			// We buffer results per repository to perform the digest selection logic.
			targets, err := r.scanRepository(ctx, repo.Name, policy)
			if err != nil {
				if !yield(ImageTarget{}, fmt.Errorf("failed to scan repo %s: %w", repo.Name, err)) {
					return
				}
				continue
			}

			// 3. Yield resolved targets
			for _, target := range targets {
				if !yield(target, nil) {
					return
				}
			}
		}
	}
}

// scanRepository fetches images from a repo, grouped by image name, and selects the matching candidates for each.
func (r *ImageResolver) scanRepository(ctx context.Context, repoName string, policy scanPolicy) ([]ImageTarget, error) {
	// Extract location and repository from repoName
	location, repository := extractLocationAndRepository(repoName)

	// Optimization: Fetch only recent images (server-side sort)
	imageReq := &artifactregistrypb.ListDockerImagesRequest{
		Parent:  repoName,
		OrderBy: "update_time desc",
	}
	it := r.client.ListDockerImages(ctx, imageReq)

	maxCandidates := policy.maxCandidates
	if maxCandidates < policy.selection.count {
		maxCandidates = policy.selection.count
	}

	// Group: ImageName -> []candidateImage
	grouped := make(map[string][]candidateImage)
	// Optimization: Track counts to stop collecting after maxCandidates per image
	counts := make(map[string]int)

	for {
		img, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		artifactReference, err := ParseArtifactURI(img.Uri)
		if err != nil {
			return nil, fmt.Errorf("invalid image URI %s: %v", img.Uri, err)
		}
		if artifactReference.Digest == nil {
			log.Warn().
				Str("uri", img.Uri).
				Msg("Skipping image without digest")
			// Skip images without digest (should not happen in GAR)
			continue
		}
		imageName := artifactReference.ImageName
		if !matchesAnyImagePattern(imageName, policy.imagePatterns) {
			continue
		}
		digest := *artifactReference.Digest

		// Skip if we already have enough candidates for this image
		if counts[imageName] >= maxCandidates {
			continue
		}

		c := candidateImage{
			Digest:     digest,
			Tags:       img.Tags,
			UpdateTime: img.UpdateTime.AsTime(),
			URI:        img.Uri,
		}
		grouped[imageName] = append(grouped[imageName], c)
		counts[imageName]++
	}

	var results []ImageTarget
	for _, name := range sortedImageNames(grouped) {
		candidates := grouped[name]
		for _, best := range selectDigests(candidates, policy.selection) {
			// Parse the URI to get ArtifactReference
			artifactRef, err := ParseArtifactURI(best.URI)
			if err != nil {
				log.Warn().Err(err).Str("uri", best.URI).Msg("Failed to parse URI, skipping image")
				continue
			}

			log.Debug().
				Str("location", location).
				Str("repository", repository).
				Str("image_name", name).
				Str("digest", best.Digest).
				Str("uri", best.URI).
				Msg("Resolved image target")

			// get one tag if available
			if len(best.Tags) > 0 {
				artifactRef.Tag = utils.ToPtr(best.Tags[0])
			}

			results = append(results, ImageTarget{
				Artifact: artifactRef,
				URI:      best.URI,
				Location: location,
			})
		}
	}

	return results, nil
}

// compiledGarRegex pre-compiles the regex for performance.
// Regex remains the same as the previous version.
var compiledGarRegex = regexp.MustCompile(`^([a-z0-9-]+-docker\.pkg\.dev)/([^/]+)/([^/]+)/([^:@]+)(?::([^@]+))?(?:@(sha256:[a-fA-F0-9]{64}))?$`)

// ParseArtifactURI parses a raw GAR URI string into a structured ArtifactReference.
func ParseArtifactURI(uri string) (schemas.ArtifactReference, error) {
	matches := compiledGarRegex.FindStringSubmatch(uri)

	if matches == nil {
		return schemas.ArtifactReference{}, fmt.Errorf("invalid GAR URI format: %s", uri)
	}

	return schemas.ArtifactReference{
		Host:         matches[1],
		ProjectID:    matches[2],
		RepositoryID: matches[3],
		ImageName:    matches[4],
		Tag:          utils.ToPtr(matches[5]),
		Digest:       utils.ToPtr(matches[6]),
	}, nil
}

func extractLocationAndRepository(repoName string) (location, repository string) {
	// Expected format: projects/{project}/locations/{location}/repositories/{repo}
	parts := strings.Split(repoName, "/")
	if len(parts) >= 6 {
		location = parts[3]   // locations/{location}
		repository = parts[5] // repositories/{repo}
	}
	return
}
