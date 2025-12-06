package drydock

import (
	"context"
	"fmt"
	"iter"
	"slices"
	"strings"
	"time"

	artifactregistry "cloud.google.com/go/artifactregistry/apiv1"
	"cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb"
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
	ImageName  string // e.g., "my-app"
	Digest     string // e.g., "sha256:..."
	URI        string // Full resource URI
	Repository string // e.g., "my-repo"
	Location   string // e.g., "us-central1"
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

			// 2. Scan the repository for targets
			// We buffer results per repository to perform the "best digest" selection logic.
			targets, err := r.scanRepository(ctx, repo.Name)
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

// scanRepository fetches images from a repo, grouped by image name, and selects the best candidate for each.
func (r *ImageResolver) scanRepository(ctx context.Context, repoName string) ([]ImageTarget, error) {
	// Extract location and repository from repoName
	location, repository := extractLocationAndRepository(repoName)

	// Optimization: Fetch only recent images (server-side sort)
	imageReq := &artifactregistrypb.ListDockerImagesRequest{
		Parent:  repoName,
		OrderBy: "update_time desc",
	}
	it := r.client.ListDockerImages(ctx, imageReq)

	// Group: ImageName -> []candidateImage
	grouped := make(map[string][]candidateImage)
	// Optimization: Track counts to stop collecting after MaxCandidates per image
	counts := make(map[string]int)

	for {
		img, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		imageName, digest, err := parseDigestFromURI(img.Uri) // Pre-validate digest format
		if err != nil {
			return nil, fmt.Errorf("invalid image URI %s: %v", img.Uri, err)
		}

		// Skip if we already have enough candidates for this image
		if counts[imageName] >= MaxCandidates {
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

	// Select the single best digest for each image group
	var results []ImageTarget
	for name, candidates := range grouped {
		best := selectBestDigest(candidates)
		if best.Digest != "" {
			results = append(results, ImageTarget{
				ImageName:  name,
				Digest:     best.Digest,
				URI:        best.URI,
				Repository: repository,
				Location:   location,
			})
		}
	}

	return results, nil
}

// selectBestDigest chooses the best candidate based on policy:
// 1. Prefer candidate with "latest" tag.
// 2. If no "latest", prefer the one with the most recent UpdateTime.
func selectBestDigest(candidates []candidateImage) candidateImage {
	if len(candidates) == 0 {
		return candidateImage{}
	}

	var newest candidateImage
	// Initialize with the first one to have a fallback
	newest = candidates[0]

	for _, c := range candidates {
		// Priority 1: Check for "latest" tag
		if slices.Contains(c.Tags, "latest") {
			return c
		}

		// Priority 2: Track the newest timestamp
		if c.UpdateTime.After(newest.UpdateTime) {
			newest = c
		}
	}

	return newest
}

// Internal Helper Functions

func isDigest(tag string) bool {
	return strings.HasPrefix(tag, "sha256:")
}

func parseDigestFromURI(uri string) (imageName string, digest string, err error) {
	// Expected format: region-docker.pkg.dev/project/repo/image@sha256:hash
	parts := strings.Split(uri, "@")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid URI format, missing '@': %s", uri)
	}
	digestPart := parts[1]
	if !strings.HasPrefix(digestPart, "sha256:") {
		return "", "", fmt.Errorf("invalid digest format, expected sha256: prefix: %s", digestPart)
	}
	return parts[0], digestPart, nil
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
