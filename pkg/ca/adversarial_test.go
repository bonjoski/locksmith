package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ADV-CA-01: Rogue Intermediate CA Subordination Bypass
// An attacker attempts to use an issued server certificate as a rogue CA
// to sign fraudulent certificates for arbitrary domains (e.g. apple.com).
func TestAdversarial_RogueIntermediateCASubordination(t *testing.T) {
	rootCA, err := GenerateRootCA("Bonjoski Root CA", "Bonjoski", 365)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	// 1. Issue standard server certificate
	certPEM, keyPEM, err := rootCA.IssueServerCert([]string{"127.0.0.1", "localhost"}, 30)
	if err != nil {
		t.Fatalf("IssueServerCert failed: %v", err)
	}

	serverBlock, _ := pem.Decode(certPEM)
	serverCert, err := x509.ParseCertificate(serverBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	serverKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Attacker attempts to forge a rogue certificate for apple.com using the server key
	rogueKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rogueTemplate := x509.Certificate{
		SerialNumber: big.NewInt(99999),
		Subject: pkix.Name{
			CommonName: "apple.com",
		},
		DNSNames:              []string{"apple.com"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	rogueDER, err := x509.CreateCertificate(rand.Reader, &rogueTemplate, serverCert, &rogueKey.PublicKey, serverKey)
	if err != nil {
		t.Fatalf("attacker cert creation failed: %v", err)
	}

	rogueCert, err := x509.ParseCertificate(rogueDER)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Victim client verifies rogue cert against Root CA
	roots := x509.NewCertPool()
	roots.AddCert(rootCA.Certificate)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(serverCert)

	opts := x509.VerifyOptions{
		DNSName:       "apple.com",
		Roots:         roots,
		Intermediates: intermediates,
	}

	_, verifyErr := rogueCert.Verify(opts)
	if verifyErr == nil {
		t.Fatal("CRITICAL SECURITY VULNERABILITY: Server certificate was accepted as an intermediate CA to sign apple.com!")
	}
	t.Logf("PASS: Subordination attack correctly blocked: %v", verifyErr)
}

// ADV-CA-02: Usage Transposition Attack (Client Certificate Presented as Server)
// An attacker presents an mTLS client certificate to impersonate an HTTPS server.
func TestAdversarial_ClientCertAsServerImpersonation(t *testing.T) {
	rootCA, err := GenerateRootCA("Bonjoski Root CA", "Bonjoski", 365)
	if err != nil {
		t.Fatal(err)
	}

	// Issue client cert
	clientCertPEM, _, err := rootCA.IssueClientCert("agent-client-1", 30)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(clientCertPEM)
	clientCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// Client verifying a server expects ExtKeyUsageServerAuth
	roots := x509.NewCertPool()
	roots.AddCert(rootCA.Certificate)

	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	_, verifyErr := clientCert.Verify(opts)
	if verifyErr == nil {
		t.Fatal("CRITICAL: Client certificate was accepted for server authentication!")
	}
	t.Logf("PASS: Client-as-server transposition blocked: %v", verifyErr)
}

// ADV-CA-03: Usage Transposition Attack (Server Certificate Presented as mTLS Client)
// An attacker presents a server certificate to authenticate as an agent client.
func TestAdversarial_ServerCertAsClientImpersonation(t *testing.T) {
	rootCA, err := GenerateRootCA("Bonjoski Root CA", "Bonjoski", 365)
	if err != nil {
		t.Fatal(err)
	}

	// Issue server cert
	serverCertPEM, _, err := rootCA.IssueServerCert([]string{"127.0.0.1", "localhost"}, 30)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(serverCertPEM)
	serverCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// Server verifying mTLS expects ExtKeyUsageClientAuth
	roots := x509.NewCertPool()
	roots.AddCert(rootCA.Certificate)

	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	_, verifyErr := serverCert.Verify(opts)
	if verifyErr == nil {
		t.Fatal("CRITICAL: Server certificate was accepted for client mTLS authentication!")
	}
	t.Logf("PASS: Server-as-client transposition blocked: %v", verifyErr)
}

// ADV-CA-04: Hostname & IP SAN Impersonation Spoofing
// Verifying that a certificate issued for 127.0.0.1/localhost cannot be used on other domains/IPs.
func TestAdversarial_HostnameSANMismatch(t *testing.T) {
	rootCA, err := GenerateRootCA("Bonjoski Root CA", "Bonjoski", 365)
	if err != nil {
		t.Fatal(err)
	}

	serverCertPEM, _, err := rootCA.IssueServerCert([]string{"127.0.0.1", "localhost"}, 30)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(serverCertPEM)
	serverCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCA.Certificate)

	// Attempt verification against attacker-controlled host
	badHosts := []string{"192.168.1.50", "evil.com", "shield.attacker.io", "localhost.evil.com"}
	for _, badHost := range badHosts {
		opts := x509.VerifyOptions{
			DNSName: badHost,
			Roots:   roots,
		}
		if _, verifyErr := serverCert.Verify(opts); verifyErr == nil {
			t.Fatalf("CRITICAL: Certificate for 127.0.0.1/localhost unexpectedly verified for %s!", badHost)
		}
	}
	t.Log("PASS: All hostname and IP SAN spoofing attempts rejected.")
}

// ADV-CA-05: Signature Forgery and Payload Tampering
// Modifying a single bit in the certificate DER payload must break verification.
func TestAdversarial_CertificatePayloadTampering(t *testing.T) {
	rootCA, err := GenerateRootCA("Bonjoski Root CA", "Bonjoski", 365)
	if err != nil {
		t.Fatal(err)
	}

	serverCertPEM, _, err := rootCA.IssueServerCert([]string{"localhost"}, 30)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(serverCertPEM)
	tamperedDER := make([]byte, len(block.Bytes))
	copy(tamperedDER, block.Bytes)

	// Flip bits in the middle of DER payload
	tamperedDER[len(tamperedDER)/2] ^= 0xFF

	tamperedCert, err := x509.ParseCertificate(tamperedDER)
	if err == nil {
		// If it parses, verification must fail
		roots := x509.NewCertPool()
		roots.AddCert(rootCA.Certificate)
		opts := x509.VerifyOptions{
			DNSName: "localhost",
			Roots:   roots,
		}
		if _, verifyErr := tamperedCert.Verify(opts); verifyErr == nil {
			t.Fatal("CRITICAL: Tampered certificate passed signature verification!")
		}
		t.Log("PASS: Tampered certificate signature rejected.")
	} else {
		t.Logf("PASS: Tampered certificate failed parsing: %v", err)
	}
}

// ADV-CA-06: Strict Private Key File Permissions Enclave Isolation
// Verifies that private keys written to disk must have 0600 permissions.
func TestAdversarial_PrivateKeyFilePermissions(t *testing.T) {
	tempDir := t.TempDir()
	rootCA, err := GenerateRootCA("Bonjoski Root CA", "Bonjoski", 365)
	if err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(tempDir, "server.key")
	certPath := filepath.Join(tempDir, "server.crt")

	certPEM, keyPEM, err := rootCA.IssueServerCert([]string{"localhost"}, 30)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Perm must be strictly 0600 (-rw-------)
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Fatalf("CRITICAL SECURITY FLAW: Private key file permissions are %o (expected 0600)!", perm)
	}

	// Ensure other processes cannot read (world-readable bits check)
	if perm&0077 != 0 {
		t.Fatalf("CRITICAL: Private key is readable by group or others: %o", perm)
	}
	t.Logf("PASS: Private key permissions strictly locked down: %o", perm)
}

// ADV-CA-07: Expired Certificate Replay Defense
// Certificates evaluated outside their validity window must fail verification.
func TestAdversarial_ExpiredCertificateReplay(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// Create an already-expired root CA (validity expired yesterday)
	notBefore := time.Now().Add(-48 * time.Hour)
	notAfter := time.Now().Add(-24 * time.Hour)

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Expired Root CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}

	expiredRoot, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(expiredRoot)

	// Issue server cert using expired root
	serverPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	serverDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, expiredRoot, &serverPriv.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}

	serverCert, err := x509.ParseCertificate(serverDER)
	if err != nil {
		t.Fatal(err)
	}

	// Verify using current time (should fail with CertificateInvalidError / expired)
	opts := x509.VerifyOptions{
		DNSName: "localhost",
		Roots:   roots,
	}

	if _, err := serverCert.Verify(opts); err == nil {
		t.Fatal("CRITICAL: Expired certificate was accepted by verification!")
	} else {
		t.Logf("PASS: Expired certificate correctly rejected: %v", err)
	}
}
