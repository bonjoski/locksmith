package ca_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
)

func TestExportContainerCerts_Formats(t *testing.T) {
	rootCA, err := ca.GenerateRootCA("Test CA", "Bonjoski Test Org", 30)
	if err != nil {
		t.Fatalf("failed to generate test root CA: %v", err)
	}

	spiffeID, err := ca.ParseSPIFFEID("spiffe://bonjoski.local/ns/dev/sa/backend-svc")
	if err != nil {
		t.Fatalf("unexpected error parsing SPIFFE ID: %v", err)
	}

	profile := &ca.SVIDProfile{
		SPIFFEID: spiffeID,
		TTL:      15 * time.Minute,
	}

	tests := []struct {
		name       string
		format     ca.ExportFormat
		svcName    string
		expectCert string
		expectKey  string
		expectCA   string
	}{
		{
			name:       "docker default",
			format:     ca.FormatDocker,
			svcName:    "",
			expectCert: "tls.crt",
			expectKey:  "tls.key",
			expectCA:   "ca.crt",
		},
		{
			name:       "docker named",
			format:     ca.FormatDocker,
			svcName:    "backend",
			expectCert: "backend.crt",
			expectKey:  "backend.key",
			expectCA:   "ca.crt",
		},
		{
			name:       "envoy",
			format:     ca.FormatEnvoy,
			svcName:    "",
			expectCert: "cert.pem",
			expectKey:  "key.pem",
			expectCA:   "ca.pem",
		},
		{
			name:       "k3s",
			format:     ca.FormatK3s,
			svcName:    "",
			expectCert: "tls.crt",
			expectKey:  "tls.key",
			expectCA:   "ca.crt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outDir := filepath.Join(t.TempDir(), "certs")
			opts := &ca.ExportOptions{
				OutDir:  outDir,
				Format:  tt.format,
				Name:    tt.svcName,
				Profile: profile,
			}

			if err := rootCA.ExportContainerCerts(opts); err != nil {
				t.Fatalf("ExportContainerCerts failed: %v", err)
			}

			// Verify directory permissions
			dirInfo, err := os.Stat(outDir)
			if err != nil {
				t.Fatalf("failed to stat export dir: %v", err)
			}
			if runtime.GOOS != "windows" {
				if dirInfo.Mode().Perm() != 0700 {
					t.Errorf("export dir perm = %o, want 0700", dirInfo.Mode().Perm())
				}
			}

			// Verify certificate file
			certPath := filepath.Join(outDir, tt.expectCert)
			certInfo, err := os.Stat(certPath)
			if err != nil {
				t.Fatalf("expected certificate at %s: %v", certPath, err)
			}
			if runtime.GOOS != "windows" {
				if certInfo.Mode().Perm() != 0644 {
					t.Errorf("cert perm = %o, want 0644", certInfo.Mode().Perm())
				}
			}

			// Verify key file (must be strictly 0600)
			keyPath := filepath.Join(outDir, tt.expectKey)
			keyInfo, err := os.Stat(keyPath)
			if err != nil {
				t.Fatalf("expected key at %s: %v", keyPath, err)
			}
			if runtime.GOOS != "windows" {
				if keyInfo.Mode().Perm() != 0600 {
					t.Errorf("key perm = %o, want 0600", keyInfo.Mode().Perm())
				}
			}

			// Verify CA root certificate file
			caPath := filepath.Join(outDir, tt.expectCA)
			if _, err := os.Stat(caPath); err != nil {
				t.Fatalf("expected CA certificate at %s: %v", caPath, err)
			}
		})
	}
}

func TestExportContainerCerts_InvalidFormat(t *testing.T) {
	rootCA, _ := ca.GenerateRootCA("Test CA", "Org", 30)
	spiffeID, _ := ca.ParseSPIFFEID("spiffe://bonjoski.local/test")
	err := rootCA.ExportContainerCerts(&ca.ExportOptions{
		OutDir:  t.TempDir(),
		Format:  "unsupported_format",
		Profile: &ca.SVIDProfile{SPIFFEID: spiffeID},
	})
	if err == nil {
		t.Errorf("expected error for unsupported format, got nil")
	}
}
