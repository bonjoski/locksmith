package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
)

// forgeRogueCert signs a certificate directly with the Root CA's private key,
// bypassing all application-level pre-issuance checks to test downstream X.509 verifier enforcement.
func forgeRogueCert(t *testing.T, rootCA *ca.CA, dnsNames []string, ipAddresses []net.IP) *x509.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed generating leaf key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "Forged Rogue Leaf",
			Organization: []string{"Attacker Organization"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, rootCA.Certificate, &leafKey.PublicKey, rootCA.PrivateKey)
	if err != nil {
		t.Fatalf("failed creating forged certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed parsing forged certificate: %v", err)
	}
	return cert
}

// ADV-CA-CHAIN-01: Go crypto/x509 Standard Library Name Constraints Rejection
// Asserts that even if an attacker completely bypasses application pre-issuance checks,
// the critical RFC 5280 Name Constraints extension embedded in the Root CA causes standard
// TLS chain verifiers to strictly reject the forged certificate.
func TestAdversarial_ChainVerification_StandardLibrary(t *testing.T) {
	rootCA, err := ca.GenerateRootCA("Bonjoski Hardened Root CA", "Bonjoski", 365)
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCA.Certificate)

	t.Run("forged public domain apple.com is rejected by x509 verifier", func(t *testing.T) {
		rogueCert := forgeRogueCert(t, rootCA, []string{"apple.com"}, nil)
		opts := x509.VerifyOptions{
			Roots:   rootPool,
			DNSName: "apple.com",
		}
		if _, err := rogueCert.Verify(opts); err == nil {
			t.Fatalf("CRITICAL SECURITY VULNERABILITY: crypto/x509 verified forged certificate for apple.com!")
		}
	})

	t.Run("forged public IP 8.8.8.8 is rejected by x509 verifier", func(t *testing.T) {
		rogueCert := forgeRogueCert(t, rootCA, nil, []net.IP{net.ParseIP("8.8.8.8")})
		opts := x509.VerifyOptions{
			Roots: rootPool,
		}
		if _, err := rogueCert.Verify(opts); err == nil {
			t.Fatalf("CRITICAL SECURITY VULNERABILITY: crypto/x509 verified forged certificate for public IP 8.8.8.8!")
		}
	})

	t.Run("legitimate localhost leaf is accepted by x509 verifier", func(t *testing.T) {
		validCert := forgeRogueCert(t, rootCA, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
		opts := x509.VerifyOptions{
			Roots:   rootPool,
			DNSName: "localhost",
		}
		if _, err := validCert.Verify(opts); err != nil {
			t.Fatalf("Expected valid localhost certificate to verify successfully, got: %v", err)
		}
	})
}

// ADV-CA-CHAIN-02: DNS Rebinding and Public Suffix Probing
// Asserts that dynamic DNS rebinding domains, public pseudo-TLDs, and homoglyphs are strictly rejected.
func TestAdversarial_DNSRebindingAndHomoglyphRejection(t *testing.T) {
	rootCA, err := ca.GenerateRootCA("Bonjoski Hardened Root CA", "Bonjoski", 365)
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	rebindingDomains := []string{
		"127.0.0.1.nip.io",
		"127-0-0-1.sslip.io",
		"localtest.me",
		"customer.internal.dev",
		"xn--80akhbyknj4f.com", // Cyrillic homoglyph
		"аpple.com",            // Unicode Cyrillic 'а'
		"localhost.attacker.com",
		"localhost.local",
	}

	for _, domain := range rebindingDomains {
		t.Run("rejects "+domain, func(t *testing.T) {
			_, _, err := rootCA.IssueServerCert([]string{domain}, 30)
			if err == nil {
				t.Fatalf("CRITICAL: Root CA signed server certificate for rebinding/homoglyph domain %q!", domain)
			}
		})
	}
}

// ADV-CA-CHAIN-03: Boundary Subnet & Multicast Range Probing
// Asserts that public boundary IP addresses, multicast, and reserved ranges cannot be issued.
func TestAdversarial_IPBoundaryRejection(t *testing.T) {
	rootCA, err := ca.GenerateRootCA("Bonjoski Hardened Root CA", "Bonjoski", 365)
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	prohibitedIPs := []string{
		"0.0.0.0",
		"8.8.8.8",
		"1.1.1.1",
		"198.18.0.1",       // Benchmark
		"224.0.0.1",        // Multicast
		"239.255.255.250",  // SSDP Multicast
		"240.0.0.1",        // Future / Reserved
		"255.255.255.255",  // Broadcast
		"2001:4860:4860::8888", // Public IPv6
		"ff02::1",          // IPv6 Multicast
	}

	for _, ipStr := range prohibitedIPs {
		t.Run("rejects "+ipStr, func(t *testing.T) {
			_, _, err := rootCA.IssueServerCert([]string{ipStr}, 30)
			if err == nil {
				t.Fatalf("CRITICAL: Root CA signed server certificate for prohibited IP %q!", ipStr)
			}
		})
	}
}
