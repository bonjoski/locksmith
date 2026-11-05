package cmd

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
)

func TestCACliCommands(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("USERPROFILE", tempHome)

	testCACliInit(t, tempHome)
	testCACliStatus(t)
	testCACliIssueServer(t, tempHome)
	testCACliIssueClient(t, tempHome)
	testCACliIssueSPIFFE(t, tempHome)
	testCACliContainerExport(t, tempHome)
	testCACliServeSpiffeHelp(t)
}

func testCACliInit(t *testing.T, tempHome string) {
	outBuf, errBuf := setupTest()
	rootCmd.SetArgs([]string{"ca", "init", "--days", "30"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("ca init failed: %v, output: %s %s", err, outBuf.String(), errBuf.String())
	}

	if !strings.Contains(outBuf.String(), "Successfully initialized Sovereign Dual-Root CA") {
		t.Errorf("unexpected output from ca init: %s", outBuf.String())
	}

	for _, name := range []string{"root-ca.crt", "root-ca-pqc.crt", "root-ca-dual.crt"} {
		p := filepath.Join(tempHome, ".locksmith", "ca", name)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			t.Fatalf("expected %s to exist at %s", name, p)
		}
	}
}

func testCACliStatus(t *testing.T) {
	statusBuf := new(bytes.Buffer)
	rootCmd.SetOut(statusBuf)
	rootCmd.SetErr(statusBuf)
	rootCmd.SetArgs([]string{"ca", "status"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("ca status failed: %v, output: %s", err, statusBuf.String())
	}

	if !strings.Contains(statusBuf.String(), "Sovereign Dual-Root Certificate Authority Status") {
		t.Errorf("unexpected output from ca status: %s", statusBuf.String())
	}
}

func testCACliIssueServer(t *testing.T, tempHome string) {
	serverBuf := new(bytes.Buffer)
	rootCmd.SetOut(serverBuf)
	rootCmd.SetErr(serverBuf)
	serverCertPath := filepath.Join(tempHome, "test-server.crt")
	serverKeyPath := filepath.Join(tempHome, "test-server.key")
	rootCmd.SetArgs([]string{"ca", "issue", "--domain", "127.0.0.1", "--domain", "localhost", "--out-cert", serverCertPath, "--out-key", serverKeyPath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("ca issue server failed: %v, output: %s", err, serverBuf.String())
	}

	if _, err := os.Stat(serverCertPath); os.IsNotExist(err) {
		t.Fatalf("expected server cert at %s", serverCertPath)
	}
}

func testCACliIssueClient(t *testing.T, tempHome string) {
	clientBuf := new(bytes.Buffer)
	rootCmd.SetOut(clientBuf)
	rootCmd.SetErr(clientBuf)
	clientCertPath := filepath.Join(tempHome, "test-client.crt")
	clientKeyPath := filepath.Join(tempHome, "test-client.key")
	rootCmd.SetArgs([]string{"ca", "issue", "--client", "--name", "agent-cursor", "--out-cert", clientCertPath, "--out-key", clientKeyPath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("ca issue client failed: %v, output: %s", err, clientBuf.String())
	}

	if _, err := os.Stat(clientCertPath); os.IsNotExist(err) {
		t.Fatalf("expected client cert at %s", clientCertPath)
	}
}

func testCACliIssueSPIFFE(t *testing.T, tempHome string) {
	spiffeBuf := new(bytes.Buffer)
	rootCmd.SetOut(spiffeBuf)
	rootCmd.SetErr(spiffeBuf)
	svidCertPath := filepath.Join(tempHome, "test-svid.crt")
	svidKeyPath := filepath.Join(tempHome, "test-svid.key")
	rootCmd.SetArgs([]string{
		"ca", "issue",
		"--spiffe", "spiffe://bonjoski.local/ns/dev/sa/worker-api",
		"--ttl", "15m",
		"--out-cert", svidCertPath,
		"--out-key", svidKeyPath,
	})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("ca issue spiffe failed: %v, output: %s", err, spiffeBuf.String())
	}

	if _, err := os.Stat(svidCertPath); os.IsNotExist(err) {
		t.Fatalf("expected spiffe svid cert at %s", svidCertPath)
	}
	if _, err := os.Stat(svidKeyPath); os.IsNotExist(err) {
		t.Fatalf("expected spiffe svid key at %s", svidKeyPath)
	}
	if !strings.Contains(spiffeBuf.String(), "spiffe://bonjoski.local/ns/dev/sa/worker-api") {
		t.Errorf("expected spiffe ID in command output: %s", spiffeBuf.String())
	}
}

func testCACliContainerExport(t *testing.T, tempHome string) {
	exportBuf := new(bytes.Buffer)
	rootCmd.SetOut(exportBuf)
	rootCmd.SetErr(exportBuf)
	exportDir := filepath.Join(tempHome, "docker-certs")
	rootCmd.SetArgs([]string{
		"ca", "container-export",
		"--name", "api-gateway",
		"--spiffe", "spiffe://bonjoski.local/ns/dev/sa/gateway",
		"--out-dir", exportDir,
		"--format", "docker",
		"--ttl", "2h",
	})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("ca container-export failed: %v, output: %s", err, exportBuf.String())
	}

	certPath := filepath.Join(exportDir, "api-gateway.crt")
	keyPath := filepath.Join(exportDir, "api-gateway.key")
	caPath := filepath.Join(exportDir, "ca.crt")

	for _, p := range []string{certPath, keyPath, caPath} {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			t.Fatalf("expected exported file to exist at %s", p)
		}
	}

	if !strings.Contains(exportBuf.String(), "Successfully exported container certificates") {
		t.Errorf("unexpected output from container-export: %s", exportBuf.String())
	}
}

func testCACliServeSpiffeHelp(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"ca", "serve-spiffe", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("ca serve-spiffe --help failed: %v", err)
	}

	out := buf.String()
	for _, expected := range []string{"--socket", "--vsock-port", "--trust-domain", "--rate-limit", "--policy"} {
		if !strings.Contains(out, expected) {
			t.Errorf("expected %s flag in ca serve-spiffe help output", expected)
		}
	}
}

func TestAdversarial_ValidateRootSecurityProfile(t *testing.T) {
	rootCA, err := ca.GenerateRootCA("Sovereign Root", "Locksmith Org", 1)
	if err != nil {
		t.Fatalf("Failed to generate default root CA: %v", err)
	}

	// 1. Valid root profile succeeds
	if err := validateRootSecurityProfile(rootCA.Certificate); err != nil {
		t.Fatalf("Expected valid root certificate profile to pass, got: %v", err)
	}

	// 2. Missing critical flag is rejected
	tamperedCert := *rootCA.Certificate
	tamperedCert.PermittedDNSDomainsCritical = false
	if err := validateRootSecurityProfile(&tamperedCert); err == nil {
		t.Fatalf("CRITICAL: Root certificate without critical Name Constraints was accepted!")
	}

	// 3. MaxPathLenZero false is rejected
	tamperedCert = *rootCA.Certificate
	tamperedCert.MaxPathLenZero = false
	if err := validateRootSecurityProfile(&tamperedCert); err == nil {
		t.Fatalf("CRITICAL: Root certificate allowing intermediate subordinate CAs was accepted!")
	}

	// 4. Missing IP ranges is rejected
	tamperedCert = *rootCA.Certificate
	tamperedCert.PermittedIPRanges = nil
	if err := validateRootSecurityProfile(&tamperedCert); err == nil {
		t.Fatalf("CRITICAL: Root certificate without PermittedIPRanges was accepted!")
	}

	// 5. Public IP range (e.g. 8.8.8.0/24) is rejected
	_, publicNet, _ := net.ParseCIDR("8.8.8.0/24")
	tamperedCert = *rootCA.Certificate
	tamperedCert.PermittedIPRanges = []*net.IPNet{publicNet}
	if err := validateRootSecurityProfile(&tamperedCert); err == nil {
		t.Fatalf("CRITICAL: Root certificate with public IP range was accepted!")
	}

	// 6. Public TLD domain (apple.com) is rejected
	tamperedCert = *rootCA.Certificate
	tamperedCert.PermittedDNSDomains = []string{"apple.com"}
	if err := validateRootSecurityProfile(&tamperedCert); err == nil {
		t.Fatalf("CRITICAL: Root certificate with public TLD (apple.com) was accepted!")
	}

	// 7. Wildcard domain (*) is rejected
	tamperedCert = *rootCA.Certificate
	tamperedCert.PermittedDNSDomains = []string{"*"}
	if err := validateRootSecurityProfile(&tamperedCert); err == nil {
		t.Fatalf("CRITICAL: Root certificate with wildcard domain (*) was accepted!")
	}

	t.Logf("PASS: validateRootSecurityProfile strictly rejects non-sovereign or unconstrained profiles.")
}
