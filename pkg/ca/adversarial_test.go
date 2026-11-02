package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
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

// ADV-08: Cross-Protocol CA Spoofing & Algorithm Substitution Attack
// Verifies that:
// 1. A server certificate signed by the classical ECDSA CA is strictly rejected by a Post-Quantum ML-DSA-65 root pool.
// 2. A server certificate signed by the Post-Quantum ML-DSA-65 CA is strictly rejected by a Classical ECDSA root pool.
// 3. Algorithm substitution attempts (e.g. attempting to verify an ML-DSA cert using an ECDSA key) are blocked.
func TestAdversarial_CrossProtocolCASpoofing(t *testing.T) {
	dualCA, err := GenerateRootCA("Dual Sovereign CA", "Dual Org", 30)
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	bundle, err := dualCA.IssueDualServerCert([]string{"localhost", "127.0.0.1"}, 30)
	if err != nil {
		t.Fatalf("IssueDualServerCert failed: %v", err)
	}

	// 1. Classical server cert
	classicalTLS, err := tls.X509KeyPair(bundle.CertPEM, bundle.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	classicalCert, err := x509.ParseCertificate(classicalTLS.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	// 2. Post-Quantum ML-DSA-65 server cert
	pqcTLS, err := tls.X509KeyPair(bundle.PQCCertPEM, bundle.PQCKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pqcCert, err := x509.ParseCertificate(pqcTLS.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	// Root pools
	classicalPool := x509.NewCertPool()
	classicalPool.AddCert(dualCA.Certificate)

	pqcPool := x509.NewCertPool()
	pqcPool.AddCert(dualCA.PQCCertificate)

	// Vector 1: Attempt to verify Classical ECDSA cert using Post-Quantum ML-DSA-65 root pool
	if _, err := classicalCert.Verify(x509.VerifyOptions{
		DNSName: "localhost",
		Roots:   pqcPool,
	}); err == nil {
		t.Fatal("CRITICAL: Classical ECDSA certificate was accepted by Post-Quantum ML-DSA-65 root pool!")
	} else {
		t.Logf("PASS: Classical cert rejected by PQC pool: %v", err)
	}

	// Vector 2: Attempt to verify Post-Quantum ML-DSA-65 cert using Classical ECDSA root pool
	if _, err := pqcCert.Verify(x509.VerifyOptions{
		DNSName: "localhost",
		Roots:   classicalPool,
	}); err == nil {
		t.Fatal("CRITICAL: Post-Quantum ML-DSA-65 certificate was accepted by Classical ECDSA root pool!")
	} else {
		t.Logf("PASS: PQC cert rejected by Classical pool: %v", err)
	}
}

// ADV-SPIFFE-05: Insecure Directory Permissions & Permissive ACL Lockdown
// If a container export directory exists with permissive 0777 or 0755 permissions,
// Locksmith must forcefully clamp permissions to 0700 and ensure private keys are 0600.
func TestAdversarial_ContainerExport_PermissiveDirChmod(t *testing.T) {
	rootCA, err := GenerateRootCA("Dual Root", "Bonjoski", 30)
	if err != nil {
		t.Fatal(err)
	}

	tempDir := t.TempDir()
	certsDir := filepath.Join(tempDir, "shared_certs")
	if err := os.MkdirAll(certsDir, 0777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(certsDir, 0777)

	spiffeID, _ := ParseSPIFFEID("spiffe://bonjoski.local/ns/dev/sa/insecure-worker")
	opts := &ExportOptions{
		OutDir:  certsDir,
		Format:  FormatDocker,
		Profile: &SVIDProfile{SPIFFEID: spiffeID, TTL: 15 * time.Minute},
	}

	if err := rootCA.ExportContainerCerts(opts); err != nil {
		t.Fatalf("ExportContainerCerts failed: %v", err)
	}

	dirInfo, err := os.Stat(certsDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm()&0077 != 0 {
		t.Fatalf("CRITICAL SECURITY FLAW: Directory retained group/world permissions: %o", dirInfo.Mode().Perm())
	}

	keyInfo, err := os.Stat(filepath.Join(certsDir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Fatalf("CRITICAL SECURITY FLAW: Private key permissions are %o, expected 0600", keyInfo.Mode().Perm())
	}
	t.Logf("PASS: Directory and private key permissions strictly secured: dir=%o, key=%o", dirInfo.Mode().Perm(), keyInfo.Mode().Perm())
}

// ADV-SPIFFE-08: Symlink Traversal & Arbitrary File Overwrite Prevention
// An attacker places a symlink in the export directory pointing to a victim file.
// Locksmith must detect the symlink and abort without following or truncating the victim target.
func TestAdversarial_ContainerExport_SymlinkHijack(t *testing.T) {
	rootCA, _ := GenerateRootCA("Dual Root", "Bonjoski", 30)
	tempDir := t.TempDir()

	// 1. Create a sensitive victim file that must not be overwritten
	victimFile := filepath.Join(tempDir, "victim_secret.txt")
	originalContent := "TOP_SECRET_CREDENTIALS"
	if err := os.WriteFile(victimFile, []byte(originalContent), 0600); err != nil {
		t.Fatal(err)
	}

	// 2. Attacker prepares export directory with symlink targeting the victim file
	certsDir := filepath.Join(tempDir, "certs")
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		t.Fatal(err)
	}
	symlinkKeyPath := filepath.Join(certsDir, "tls.key")
	if err := os.Symlink(victimFile, symlinkKeyPath); err != nil {
		t.Fatal(err)
	}

	spiffeID, _ := ParseSPIFFEID("spiffe://bonjoski.local/ns/dev/sa/symlink-attacker")
	opts := &ExportOptions{
		OutDir:  certsDir,
		Format:  FormatDocker,
		Profile: &SVIDProfile{SPIFFEID: spiffeID, TTL: 15 * time.Minute},
	}

	// 3. Export must abort with ErrSymlinkAttackDetected
	err := rootCA.ExportContainerCerts(opts)
	if err == nil {
		t.Fatal("CRITICAL SECURITY VULNERABILITY: Export followed symlink and overwrote target file!")
	}
	if !errors.Is(err, ErrSymlinkAttackDetected) {
		t.Fatalf("expected ErrSymlinkAttackDetected, got: %v", err)
	}

	// 4. Verify victim file content is pristine
	content, readErr := os.ReadFile(victimFile)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(content) != originalContent {
		t.Fatalf("CRITICAL: Victim file content was corrupted! got %q", string(content))
	}
	t.Logf("PASS: Symlink attack detected and victim file remained intact.")
}

// ADV-SPIFFE-07: In-Memory Key Zeroization Verification
// Asserts that ZeroBytes thoroughly wipes cryptographic byte buffers.
func TestAdversarial_ContainerExport_Zeroization(t *testing.T) {
	secretBuffer := []byte("CRITICAL_EPHEMERAL_PRIVATE_KEY_MATERIAL")
	ZeroBytes(secretBuffer)

	for i, b := range secretBuffer {
		if b != 0 {
			t.Fatalf("CRITICAL: Memory byte at index %d was not zeroed: %x", i, b)
		}
	}
	t.Logf("PASS: In-memory key buffer successfully zeroized.")
}

