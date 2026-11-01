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
	rootCA, err := GenerateRootCA("Bonjoski Root CA", "Bonjoski", 365)
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
