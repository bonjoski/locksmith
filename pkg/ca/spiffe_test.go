package ca_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
)

func TestParseSPIFFEID_Table(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantErr     bool
		trustDomain string
		path        string
	}{
		{
			name:        "valid standard ID",
			input:       "spiffe://bonjoski.local/ns/dev/sa/api",
			wantErr:     false,
			trustDomain: "bonjoski.local",
			path:        "ns/dev/sa/api",
		},
		{
			name:        "valid multi-segment path",
			input:       "spiffe://domain.org/a/b/c/d/e",
			wantErr:     false,
			trustDomain: "domain.org",
			path:        "a/b/c/d/e",
		},
		{
			name:    "missing scheme",
			input:   "bonjoski.local/ns/dev/sa/api",
			wantErr: true,
		},
		{
			name:    "wrong scheme https",
			input:   "https://bonjoski.local/ns/dev/sa/api",
			wantErr: true,
		},
		{
			name:    "path traversal attempt with parent directory",
			input:   "spiffe://bonjoski.local/../../root",
			wantErr: true,
		},
		{
			name:    "query params forbidden",
			input:   "spiffe://bonjoski.local/service?role=admin",
			wantErr: true,
		},
		{
			name:    "fragment forbidden",
			input:   "spiffe://bonjoski.local/service#anchor",
			wantErr: true,
		},
		{
			name:    "null byte injection",
			input:   "spiffe://bonjoski.local/service\x00/evil",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "missing path",
			input:   "spiffe://bonjoski.local",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ca.ParseSPIFFEID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseSPIFFEID(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if err == nil {
				if parsed.String() != tt.input {
					t.Errorf("got String() = %q, want %q", parsed.String(), tt.input)
				}
				if parsed.TrustDomain() != tt.trustDomain {
					t.Errorf("got TrustDomain() = %q, want %q", parsed.TrustDomain(), tt.trustDomain)
				}
				if parsed.Path() != tt.path {
					t.Errorf("got Path() = %q, want %q", parsed.Path(), tt.path)
				}
				if parsed.URL() == nil || parsed.URL().Scheme != "spiffe" {
					t.Errorf("parsed URL missing or invalid scheme: %v", parsed.URL())
				}
			}
		})
	}
}

func parseTestCertificate(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("failed to decode certificate PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

func verifyCertURIs(t *testing.T, cert *x509.Certificate, expected string) {
	t.Helper()
	if len(cert.URIs) != 1 || cert.URIs[0].String() != expected {
		t.Errorf("URI SAN mismatch: got %v, want %s", cert.URIs, expected)
	}
}

func verifyCertHosts(t *testing.T, cert *x509.Certificate, expectedDNS, expectedIP string) {
	t.Helper()
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != expectedDNS {
		t.Errorf("unexpected DNSNames: %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != expectedIP {
		t.Errorf("unexpected IPAddresses: %v", cert.IPAddresses)
	}
}

func verifyCertTimestamps(t *testing.T, cert *x509.Certificate, now time.Time, ttl time.Duration) {
	t.Helper()
	expectedSkew := now.Add(-5 * time.Minute)
	if cert.NotBefore.After(expectedSkew.Add(30 * time.Second)) || cert.NotBefore.Before(expectedSkew.Add(-30*time.Second)) {
		t.Errorf("NotBefore skew outside expected range: got %v", cert.NotBefore)
	}
	expectedNotAfter := now.Add(ttl)
	if cert.NotAfter.After(expectedNotAfter.Add(30*time.Second)) || cert.NotAfter.Before(expectedNotAfter.Add(-30*time.Second)) {
		t.Errorf("NotAfter outside expected range: got %v", cert.NotAfter)
	}
}

func verifyCertUsages(t *testing.T, cert *x509.Certificate) {
	t.Helper()
	if cert.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment) == 0 {
		t.Errorf("missing expected KeyUsage bits: %v", cert.KeyUsage)
	}
	hasServerAuth, hasClientAuth := false, false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasServerAuth || !hasClientAuth {
		t.Errorf("expected dual ExtKeyUsage, got: %v", cert.ExtKeyUsage)
	}
}

func verifyCertChain(t *testing.T, cert, root *x509.Certificate, now time.Time) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(root)
	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := cert.Verify(opts); err != nil {
		t.Fatalf("failed to verify SVID against root CA: %v", err)
	}
}

func TestIssueSVID_Classical(t *testing.T) {
	rootCA, err := ca.GenerateRootCAWithConfig(ca.RootCAConfig{
		CommonName:          "Test CA",
		Organization:        "Bonjoski Test Org",
		ValidityDays:        30,
		PermittedDNSDomains: []string{"localhost", ".localhost", ".internal"},
	})
	if err != nil {
		t.Fatalf("failed to generate test root CA: %v", err)
	}

	spiffeID, err := ca.ParseSPIFFEID("spiffe://bonjoski.local/ns/dev/sa/payment-api")
	if err != nil {
		t.Fatalf("unexpected error parsing SPIFFE ID: %v", err)
	}

	profile := &ca.SVIDProfile{
		SPIFFEID: spiffeID,
		Hosts:    []string{"127.0.0.1", "api.internal"},
		TTL:      15 * time.Minute,
	}

	certPEM, keyPEM, err := rootCA.IssueSVID(profile)
	if err != nil {
		t.Fatalf("failed to issue SVID: %v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatalf("empty cert or key PEM returned")
	}

	cert := parseTestCertificate(t, certPEM)
	now := time.Now()

	verifyCertURIs(t, cert, spiffeID.String())
	verifyCertHosts(t, cert, "api.internal", "127.0.0.1")
	verifyCertTimestamps(t, cert, now, 15*time.Minute)
	verifyCertUsages(t, cert)
	verifyCertChain(t, cert, rootCA.Certificate, now)
}

func TestIssueDualSVID_PostQuantum(t *testing.T) {
	rootCA, err := ca.GenerateRootCA("Dual Root CA", "Bonjoski PQC", 30)
	if err != nil {
		t.Fatalf("failed to generate dual root CA: %v", err)
	}

	spiffeID, err := ca.ParseSPIFFEID("spiffe://bonjoski.local/ns/dev/sa/pqc-worker")
	if err != nil {
		t.Fatalf("unexpected error parsing SPIFFE ID: %v", err)
	}

	bundle, err := rootCA.IssueDualSVID(&ca.SVIDProfile{
		SPIFFEID: spiffeID,
		TTL:      30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to issue dual SVID: %v", err)
	}

	if len(bundle.CertPEM) == 0 || len(bundle.KeyPEM) == 0 {
		t.Errorf("missing classical cert/key PEM")
	}
	if len(bundle.PQCCertPEM) == 0 || len(bundle.PQCKeyPEM) == 0 {
		t.Errorf("missing PQC cert/key PEM")
	}
	if len(bundle.DualCertPEM) == 0 {
		t.Errorf("missing concatenated DualCertPEM")
	}

	pqcCert := parseTestCertificate(t, bundle.PQCCertPEM)
	if pqcCert.SignatureAlgorithm != x509.MLDSA65 {
		t.Errorf("expected ML-DSA-65 signature algorithm, got: %v", pqcCert.SignatureAlgorithm)
	}
	if len(pqcCert.URIs) != 1 || pqcCert.URIs[0].String() != spiffeID.String() {
		t.Errorf("PQC SVID missing or incorrect URI SAN: %v", pqcCert.URIs)
	}
}

func TestIssueSVID_TTLLimits(t *testing.T) {
	rootCA, err := ca.GenerateRootCA("Test CA", "Bonjoski Org", 30)
	if err != nil {
		t.Fatalf("failed to generate test root CA: %v", err)
	}

	spiffeID, _ := ca.ParseSPIFFEID("spiffe://bonjoski.local/test/workload")

	// Over 24 hours rejected
	_, _, err = rootCA.IssueSVID(&ca.SVIDProfile{
		SPIFFEID: spiffeID,
		TTL:      25 * time.Hour,
	})
	if err == nil {
		t.Errorf("expected error for TTL > 24h, got nil")
	}

	// Under 1 minute rejected
	_, _, err = rootCA.IssueSVID(&ca.SVIDProfile{
		SPIFFEID: spiffeID,
		TTL:      30 * time.Second,
	})
	if err == nil {
		t.Errorf("expected error for TTL < 1m, got nil")
	}

	// 0 duration defaults to 1 hour
	certPEM, _, err := rootCA.IssueSVID(&ca.SVIDProfile{
		SPIFFEID: spiffeID,
		TTL:      0,
	})
	if err != nil {
		t.Fatalf("unexpected error for 0 TTL: %v", err)
	}
	cert := parseTestCertificate(t, certPEM)
	now := time.Now()
	expectedNotAfter := now.Add(1 * time.Hour)
	if cert.NotAfter.After(expectedNotAfter.Add(30*time.Second)) || cert.NotAfter.Before(expectedNotAfter.Add(-30*time.Second)) {
		t.Errorf("NotAfter for default TTL outside expected range: got %v, want near %v", cert.NotAfter, expectedNotAfter)
	}
}
