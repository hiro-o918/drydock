package utils

import (
	"context"
	"fmt"
	"os"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2/google"
)

// GetProjectID attempts to determine the GCP project ID from the environment.
// It checks in the following order:
// 1. Environment variables (GOOGLE_CLOUD_PROJECT, GCLOUD_PROJECT)
// 2. Application Default Credentials (ADC)
// 3. GCP metadata server (if running on GCP)
// Returns an error if no project ID could be determined.
func GetProjectID(ctx context.Context) (string, error) {
	// 1. Check environment variables
	if p := os.Getenv("GOOGLE_CLOUD_PROJECT"); p != "" {
		return p, nil
	}
	if p := os.Getenv("GCLOUD_PROJECT"); p != "" {
		return p, nil
	}

	// 2. Check Application Default Credentials (ADC)
	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err == nil && creds.ProjectID != "" {
		return creds.ProjectID, nil
	}

	// 3. Check metadata server (only on GCP)
	if metadata.OnGCE() {
		p, err := metadata.ProjectIDWithContext(ctx)
		if err == nil && p != "" {
			return p, nil
		}
	}

	return "", fmt.Errorf("project ID not found in environment variables, credentials, or metadata server")
}
