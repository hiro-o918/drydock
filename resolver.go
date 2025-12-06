package drydock

import (
	"context"
	"fmt"
	"iter"
	"strings"
	"time"

	artifactregistry "cloud.google.com/go/artifactregistry/apiv1"
	"cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb"
	"google.golang.org/api/iterator"
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
	ImageName string // e.g., "my-app"
	Digest    string // e.g., "sha256:..."
	URI       string // Full resource URI
}

// candidateImage is an internal struct used for selection logic.
type candidateImage struct {
	Digest     string
	Tags       []string
	UpdateTime time.Time
	URI        string
}

// NewImageResolver creates a new resolver with ADC authentication.
func NewImageResolver(ctx context.Context) (*ImageResolver, error) {
	client, err := artifactregistry.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Artifact Registry client: %w", err)
	}
	return &ImageResolver{client: client}, nil
}

// Close closes the underlying API client.
func (r *ImageResolver) Close() error {
	return r.client.Close()
}

// ResolveDigest retrieves the SHA256 digest for a given image tag.
func (r *ImageResolver) ResolveDigest(ctx context.Context, projectID, location, repo, image, tag string) (string, error) {
	// Logic: Skip API if already a digest
	if isDigest(tag) {
		return tag, nil
	}

	fullImageName := fmt.Sprintf("projects/%s/locations/%s/repositories/%s/dockerImages/%s:%s",
		projectID, location, repo, image, tag)

	req := &artifactregistrypb.GetDockerImageRequest{
		Name: fullImageName,
	}

	// API Call (Not tested in unit tests)
	resp, err := r.client.GetDockerImage(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to resolve tag '%s': %w", tag, err)
	}

	// Logic: Parse response
	return parseDigestFromURI(resp.Uri)
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

		// Parse Image Name (e.g. "my-app") from URI
		// URI format: region-docker.pkg.dev/project/repo/image@sha256:hash
		parts := strings.Split(img.Uri, "@")
		if len(parts) < 2 {
			continue
		}
		pathParts := strings.Split(parts[0], "/")
		imageName := pathParts[len(pathParts)-1]

		// Skip if we already have enough candidates for this image
		if counts[imageName] >= MaxCandidates {
			continue
		}

		digest := ""
		if strings.HasPrefix(parts[1], "sha256:") {
			digest = parts[1]
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
				ImageName: name,
				Digest:    best.Digest,
				URI:       best.URI,
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
		for _, t := range c.Tags {
			if t == "latest" {
				return c
			}
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

func parseDigestFromURI(uri string) (string, error) {
	// Expected format: region-docker.pkg.dev/project/repo/image@sha256:hash
	parts := strings.Split(uri, "@")
	if len(parts) != 2 {
		return "", fmt.Errorf("unexpected image URI format: %s", uri)
	}
	if !strings.HasPrefix(parts[1], "sha256:") {
		return "", fmt.Errorf("invalid digest format in URI: %s", parts[1])
	}
	return parts[1], nil
}
