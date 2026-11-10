package ca

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestRootCAGenerationAndValidation(t *testing.T) {
	ca, err := GenerateRootCA("Test Sovereign CA", "Test Org", 30)
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	if ca.Certificate == nil || ca.PrivateKey == nil {
		t.Fatal("expected non-nil Certificate and PrivateKey")
	}

	if !ca.Certificate.IsCA {
		t.Errorf("expected IsCA to be true")
	}
	if ca.Certificate.Subject.CommonName != "Test Sovereign CA" {
		t.Errorf("unexpected CommonName: %s", ca.Certificate.Subject.CommonName)
	}

	// Verify self-signed
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)

	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := ca.Certificate.Verify(opts); err != nil {
		t.Fatalf("self-signed verification failed: %v", err)
	}

	// Test reload
	reloaded, err := LoadCA(ca.CertPEM, ca.KeyPEM)
	if err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}
	if reloaded.Certificate.Subject.CommonName != ca.Certificate.Subject.CommonName {
		t.Errorf("reloaded CA common name mismatch")
	}
}

func TestIssueServerCertAndVerification(t *testing.T) {
	rootCA, err := GenerateRootCAWithConfig(RootCAConfig{
		CommonName:          "Bonjoski Root CA",
		Organization:        "Bonjoski",
		ValidityDays:        365,
		PermittedDNSDomains: []string{"localhost", ".localhost", ".local"},
	})
	if err != nil {
		t.Fatal(err)
	}

	hosts := []string{"127.0.0.1", "localhost", "shield.local"}
	certPEM, keyPEM, err := rootCA.IssueServerCert(hosts, 30)
	if err != nil {
		t.Fatalf("IssueServerCert failed: %v", err)
	}

	// Verify keypair loads into crypto/tls
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair failed: %v", err)
	}

	serverCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	// Check SANs
	if len(serverCert.DNSNames) != 2 || serverCert.DNSNames[0] != "localhost" || serverCert.DNSNames[1] != "shield.local" {
		t.Errorf("unexpected DNSNames: %v", serverCert.DNSNames)
	}
	if len(serverCert.IPAddresses) != 1 || serverCert.IPAddresses[0].String() != "127.0.0.1" {
		t.Errorf("unexpected IPAddresses: %v", serverCert.IPAddresses)
	}

	// Cryptographic chain verification against Root CA
	roots := x509.NewCertPool()
	roots.AddCert(rootCA.Certificate)

	verifyOpts := x509.VerifyOptions{
		DNSName: "localhost",
		Roots:   roots,
	}
	if _, err := serverCert.Verify(verifyOpts); err != nil {
		t.Fatalf("server certificate verification failed: %v", err)
	}
}

func TestIssueClientCertAndVerification(t *testing.T) {
	rootCA, err := GenerateRootCA("Bonjoski Root CA", "Bonjoski", 365)
	if err != nil {
		t.Fatal(err)
	}

	certPEM, keyPEM, err := rootCA.IssueClientCert("agent-cursor", 30)
	if err != nil {
		t.Fatalf("IssueClientCert failed: %v", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair failed: %v", err)
	}

	clientCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	if clientCert.Subject.CommonName != "agent-cursor" {
		t.Errorf("unexpected client common name: %s", clientCert.Subject.CommonName)
	}

	// Check client auth key usage
	hasClientAuth := false
	for _, usage := range clientCert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}
	if !hasClientAuth {
		t.Errorf("expected ExtKeyUsageClientAuth")
	}

	// Cryptographic chain verification
	roots := x509.NewCertPool()
	roots.AddCert(rootCA.Certificate)

	verifyOpts := x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Roots:     roots,
	}
	if _, err := clientCert.Verify(verifyOpts); err != nil {
		t.Fatalf("client certificate verification failed: %v", err)
	}
}

func TestDualRootCAGeneration(t *testing.T) {
	dualCA, err := GenerateRootCA("Dual Sovereign CA", "Dual Org", 30)
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	if dualCA.Certificate == nil || dualCA.PrivateKey == nil {
		t.Fatal("expected classical Certificate and PrivateKey")
	}
	if dualCA.PQCCertificate == nil || dualCA.PQCPrivateKey == nil {
		t.Fatal("expected post-quantum PQCCertificate and PQCPrivateKey")
	}
	if dualCA.PQCCertificate.SignatureAlgorithm != x509.MLDSA65 {
		t.Errorf("expected ML-DSA-65 signature algorithm, got: %s", dualCA.PQCCertificate.SignatureAlgorithm)
	}
}

func TestDualRootReload(t *testing.T) {
	dualCA, err := GenerateRootCA("Dual Sovereign CA", "Dual Org", 30)
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	reloaded, err := LoadDualCA(dualCA.CertPEM, dualCA.KeyPEM, dualCA.PQCCertPEM, dualCA.PQCKeyPEM)
	if err != nil {
		t.Fatalf("LoadDualCA failed: %v", err)
	}
	if reloaded.PQCCertificate == nil {
		t.Fatal("expected non-nil PQCCertificate after LoadDualCA")
	}
}

func TestDualRootServerCertIssuance(t *testing.T) {
	dualCA, err := GenerateRootCA("Dual Sovereign CA", "Dual Org", 30)
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	bundle, err := dualCA.IssueDualServerCert([]string{"127.0.0.1", "localhost"}, 30)
	if err != nil {
		t.Fatalf("IssueDualServerCert failed: %v", err)
	}

	if len(bundle.CertPEM) == 0 || len(bundle.KeyPEM) == 0 {
		t.Fatal("expected non-empty classical cert and key")
	}
	if len(bundle.PQCCertPEM) == 0 || len(bundle.PQCKeyPEM) == 0 {
		t.Fatal("expected non-empty PQC cert and key")
	}

	pqcPool := x509.NewCertPool()
	pqcPool.AddCert(dualCA.PQCCertificate)

	pqcServerTLS, err := tls.X509KeyPair(bundle.PQCCertPEM, bundle.PQCKeyPEM)
	if err != nil {
		t.Fatalf("failed to parse PQC server keypair into tls.X509KeyPair: %v", err)
	}
	pqcServerCert, err := x509.ParseCertificate(pqcServerTLS.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse PQC server cert: %v", err)
	}

	if _, err := pqcServerCert.Verify(x509.VerifyOptions{
		DNSName: "localhost",
		Roots:   pqcPool,
	}); err != nil {
		t.Fatalf("PQC server certificate verification failed: %v", err)
	}
}

func TestDualRootClientCertIssuance(t *testing.T) {
	dualCA, err := GenerateRootCA("Dual Sovereign CA", "Dual Org", 30)
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	clientBundle, err := dualCA.IssueDualClientCert("agent-pqc", 30)
	if err != nil {
		t.Fatalf("IssueDualClientCert failed: %v", err)
	}
	if len(clientBundle.PQCCertPEM) == 0 {
		t.Fatal("expected non-empty PQC client cert")
	}
}

func TestParanoidCAIntegration(t *testing.T) {
	// 1. GenerateRootCA runs pre-flight RNG health and key checks
	rootCA, err := GenerateRootCAWithConfig(RootCAConfig{
		CommonName:   "Paranoid Verified Root CA",
		Organization: "Bonjoski Paranoid Test",
		ValidityDays: 365,
	})
	if err != nil {
		t.Fatalf("GenerateRootCAWithConfig failed: %v", err)
	}

	// 2. Issue server cert runs paranoid checks on leaf
	certPEM, keyPEM, err := rootCA.IssueServerCert([]string{"localhost", "127.0.0.1"}, 30)
	if err != nil {
		t.Fatalf("IssueServerCert failed: %v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("expected non-empty cert and key")
	}

	// 3. Issue SPIFFE SVID runs paranoid checks
	spiffeID, err := ParseSPIFFEID("spiffe://bonjoski.local/ns/test/sa/agent-worker")
	if err != nil {
		t.Fatalf("ParseSPIFFEID failed: %v", err)
	}
	svidCertPEM, svidKeyPEM, err := rootCA.IssueSVID(&SVIDProfile{
		SPIFFEID: spiffeID,
	})
	if err != nil {
		t.Fatalf("IssueSVID failed: %v", err)
	}
	if len(svidCertPEM) == 0 || len(svidKeyPEM) == 0 {
		t.Fatal("expected non-empty SVID cert and key")
	}

	// 4. Test LoadCA with tampered/corrupted certificate is rejected
	corruptedCertPEM := []byte("-----BEGIN CERTIFICATE-----\nZmFrZWNlcnRpZmljYXRlCg==\n-----END CERTIFICATE-----\n")
	if _, err := LoadCA(corruptedCertPEM, rootCA.KeyPEM); err == nil {
		t.Error("expected LoadCA to reject corrupted certificate")
	}
}


