package main

import "testing"

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
