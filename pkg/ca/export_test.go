package ca_test

import (
	"crypto/x509"
	"encoding/pem"
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

func assertGoldenFilesExist(t *testing.T, outDir string) ([]byte, []byte) {
	t.Helper()
	certFile := filepath.Join(outDir, "tls.crt")
	keyFile := filepath.Join(outDir, "tls.key")
	caFile := filepath.Join(outDir, "ca.crt")

	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("missing golden contract file tls.crt: %v", err)
	}
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("missing golden contract file tls.key: %v", err)
	}
	if _, err := os.ReadFile(caFile); err != nil {
		t.Fatalf("missing golden contract file ca.crt: %v", err)
	}
	return certBytes, keyBytes
}

func parseLeafCert(t *testing.T, certBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("failed decoding tls.crt PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed parsing leaf certificate: %v", err)
	}
	return cert
}

func assertLeafCertUsage(t *testing.T, cert *x509.Certificate, requestedTTL time.Duration) {
	t.Helper()
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("golden contract violation: leaf cert must be ECDSA P-256, got: %v", cert.PublicKeyAlgorithm)
	}
	expectedUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if (cert.KeyUsage & expectedUsage) == 0 {
		t.Errorf("golden contract violation: leaf cert KeyUsage must contain DigitalSignature and KeyEncipherment")
	}
	hasServer, hasClient := false, false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServer = true
		}
		if eku == x509.ExtKeyUsageClientAuth {
			hasClient = true
		}
	}
	if !hasServer || !hasClient {
		t.Errorf("golden contract violation: leaf cert ExtKeyUsage must include ServerAuth and ClientAuth")
	}
	if cert.NotBefore.After(time.Now()) {
		t.Errorf("golden contract violation: NotBefore %v must be backdated before current time", cert.NotBefore)
	}
	validity := cert.NotAfter.Sub(cert.NotBefore)
	if validity < requestedTTL || validity > requestedTTL+10*time.Minute {
		t.Errorf("golden contract violation: cert validity %v outside expected bounds for requested TTL %v", validity, requestedTTL)
	}
}

func assertCertSANs(t *testing.T, cert *x509.Certificate, expectedURI string, expectedDNS string) {
	t.Helper()
	foundURI, foundDNS := false, false
	for _, uri := range cert.URIs {
		if uri.String() == expectedURI {
			foundURI = true
			break
		}
	}
	if !foundURI {
		t.Errorf("golden contract violation: leaf cert missing SPIFFE URI SAN %s: %v", expectedURI, cert.URIs)
	}
	for _, dns := range cert.DNSNames {
		if dns == expectedDNS {
			foundDNS = true
			break
		}
	}
	if !foundDNS {
		t.Errorf("golden contract violation: leaf cert missing DNS SAN %s: %v", expectedDNS, cert.DNSNames)
	}
}

func assertAtomicRotation(t *testing.T, rootCA *ca.CA, opts *ca.ExportOptions, outDir string, origKey []byte) {
	t.Helper()
	time.Sleep(10 * time.Millisecond)
	if err := rootCA.ExportContainerCerts(opts); err != nil {
		t.Fatalf("rotation ExportContainerCerts failed: %v", err)
	}
	newKeyBytes, err := os.ReadFile(filepath.Join(outDir, "tls.key"))
	if err != nil {
		t.Fatalf("failed reading rotated tls.key: %v", err)
	}
	if string(newKeyBytes) == string(origKey) {
		t.Errorf("golden contract violation: expected fresh private key on rotation export")
	}
	entries, _ := os.ReadDir(outDir)
	for _, entry := range entries {
		name := entry.Name()
		if name != "tls.crt" && name != "tls.key" && name != "ca.crt" {
			t.Errorf("golden contract violation: unexpected file or dotfile in export dir: %s", name)
		}
	}
}

// Consumer Contract Golden Test for container-export:
// Asserts exact filenames (tls.crt, tls.key, ca.crt), classical-only leaf,
// URI & DNS SANs, KeyUsage & ExtKeyUsage, NotBefore backdating, TTL bounds,
// and atomic replacement on rotation.
func TestExportContainerCerts_ConsumerGoldenContract(t *testing.T) {
	rootCA, err := ca.GenerateRootCAWithConfig(ca.RootCAConfig{
		CommonName:          "Sovereign Root CA",
		Organization:        "Bonjoski Golden Contract",
		ValidityDays:        365,
		PermittedDNSDomains: []string{"localhost", ".localhost", "payment.local"},
		PermittedURIDomains: []string{"bonjoski.local"},
	})
	if err != nil {
		t.Fatalf("failed generating root CA: %v", err)
	}

	spiffeID, err := ca.ParseSPIFFEID("spiffe://bonjoski.local/ns/prod/sa/payment-service")
	if err != nil {
		t.Fatalf("failed parsing SPIFFE ID: %v", err)
	}

	outDir := filepath.Join(t.TempDir(), "golden-certs")
	requestedTTL := 30 * time.Minute
	profile := &ca.SVIDProfile{
		SPIFFEID: spiffeID,
		Hosts:    []string{"payment.local", "127.0.0.1"},
		TTL:      requestedTTL,
	}
	opts := &ca.ExportOptions{
		OutDir:  outDir,
		Format:  ca.FormatDocker,
		Profile: profile,
	}

	if err := rootCA.ExportContainerCerts(opts); err != nil {
		t.Fatalf("ExportContainerCerts failed: %v", err)
	}

	certBytes, keyBytes := assertGoldenFilesExist(t, outDir)
	cert := parseLeafCert(t, certBytes)
	assertLeafCertUsage(t, cert, requestedTTL)
	assertCertSANs(t, cert, "spiffe://bonjoski.local/ns/prod/sa/payment-service", "payment.local")
	assertAtomicRotation(t, rootCA, opts, outDir, keyBytes)
}
