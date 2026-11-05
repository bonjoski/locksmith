package cmd

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
	"github.com/bonjoski/locksmith/v2/pkg/spiffe"
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

func TestAdversarial_ValidateRootSecurityProfile_Basic(t *testing.T) {
	rootCA, err := ca.GenerateRootCA("Sovereign Root", "Locksmith Org", 1)
	if err != nil {
		t.Fatalf("Failed to generate default root CA: %v", err)
	}

	if err := validateRootSecurityProfile(rootCA.Certificate); err != nil {
		t.Fatalf("Expected valid root certificate profile to pass, got: %v", err)
	}

	tampered := *rootCA.Certificate
	tampered.PermittedDNSDomainsCritical = false
	if err := validateRootSecurityProfile(&tampered); err == nil {
		t.Fatalf("CRITICAL: Root certificate without critical Name Constraints was accepted!")
	}

	tampered = *rootCA.Certificate
	tampered.MaxPathLenZero = false
	if err := validateRootSecurityProfile(&tampered); err == nil {
		t.Fatalf("CRITICAL: Root certificate allowing intermediate subordinate CAs was accepted!")
	}

	tampered = *rootCA.Certificate
	tampered.PermittedIPRanges = nil
	if err := validateRootSecurityProfile(&tampered); err == nil {
		t.Fatalf("CRITICAL: Root certificate without PermittedIPRanges was accepted!")
	}
}

func TestAdversarial_ValidateRootSecurityProfile_IPConstraints(t *testing.T) {
	rootCA, err := ca.GenerateRootCA("Sovereign Root", "Locksmith Org", 1)
	if err != nil {
		t.Fatalf("Failed to generate default root CA: %v", err)
	}

	// Public IP range
	_, publicNet, _ := net.ParseCIDR("8.8.8.0/24")
	tampered := *rootCA.Certificate
	tampered.PermittedIPRanges = []*net.IPNet{publicNet}
	if err := validateRootSecurityProfile(&tampered); err == nil {
		t.Fatalf("CRITICAL: Root certificate with public IP range was accepted!")
	}

	// Supernet 0 CIDR bypass
	_, supernetNet, _ := net.ParseCIDR("127.0.0.0/0")
	tampered = *rootCA.Certificate
	tampered.PermittedIPRanges = []*net.IPNet{supernetNet}
	if err := validateRootSecurityProfile(&tampered); err == nil {
		t.Fatalf("CRITICAL: Supernet /0 CIDR bypass (127.0.0.0/0) was accepted!")
	}

	// Supernet 7 CIDR bypass
	_, supernet7, _ := net.ParseCIDR("127.0.0.0/7")
	tampered = *rootCA.Certificate
	tampered.PermittedIPRanges = []*net.IPNet{supernet7}
	if err := validateRootSecurityProfile(&tampered); err == nil {
		t.Fatalf("CRITICAL: Supernet /7 CIDR bypass (127.0.0.0/7) was accepted!")
	}

	// IPv6 supernet 0
	_, supernetIPv6, _ := net.ParseCIDR("::/0")
	tampered = *rootCA.Certificate
	tampered.PermittedIPRanges = []*net.IPNet{supernetIPv6}
	if err := validateRootSecurityProfile(&tampered); err == nil {
		t.Fatalf("CRITICAL: IPv6 supernet /0 was accepted!")
	}

	// Multicast IP range
	_, multicastNet, _ := net.ParseCIDR("224.0.0.0/4")
	tampered = *rootCA.Certificate
	tampered.PermittedIPRanges = []*net.IPNet{multicastNet}
	if err := validateRootSecurityProfile(&tampered); err == nil {
		t.Fatalf("CRITICAL: Multicast IP range was accepted!")
	}
}

func TestAdversarial_ValidateRootSecurityProfile_DNSAndURIs(t *testing.T) {
	rootCA, err := ca.GenerateRootCA("Sovereign Root", "Locksmith Org", 1)
	if err != nil {
		t.Fatalf("Failed to generate default root CA: %v", err)
	}

	for _, d := range []string{"apple.com", "*", "com", "org", "bonjoski.lan", "example.eu", "google.de", "corp.co.uk", "sub.cloud"} {
		tampered := *rootCA.Certificate
		tampered.PermittedDNSDomains = []string{d}
		if err := validateRootSecurityProfile(&tampered); err == nil {
			t.Fatalf("CRITICAL: Invalid domain constraint %q was accepted!", d)
		}
	}

	for _, u := range []string{"https://google.com", "local.dev"} {
		tampered := *rootCA.Certificate
		tampered.PermittedURIDomains = []string{u}
		if err := validateRootSecurityProfile(&tampered); err == nil {
			t.Fatalf("CRITICAL: Public URI domain constraint %q was accepted!", u)
		}
	}

	tampered := *rootCA.Certificate
	tampered.PermittedURIDomains = []string{"spiffe://bonjoski.local"}
	if err := validateRootSecurityProfile(&tampered); err != nil {
		t.Fatalf("Expected sovereign URI domain constraint 'spiffe://bonjoski.local' to pass, got: %v", err)
	}
}

func TestParsePermittedIPs(t *testing.T) {
	// 1. Valid IPs and CIDRs
	validRaw := []string{"127.0.0.1", "10.0.0.0/8", "::1"}
	nets, err := parsePermittedIPs(validRaw)
	if err != nil {
		t.Fatalf("unexpected error parsing valid IPs: %v", err)
	}
	if len(nets) != 3 {
		t.Fatalf("expected 3 nets, got %d", len(nets))
	}

	// Ensure IPv4 representations are 4 bytes
	if len(nets[0].IP) != 4 {
		t.Errorf("expected 4-byte IPv4 for 127.0.0.1, got %d bytes", len(nets[0].IP))
	}
	if len(nets[1].IP) != 4 {
		t.Errorf("expected 4-byte IPv4 for 10.0.0.0/8, got %d bytes", len(nets[1].IP))
	}

	// 2. Invalid IP returns error (fails closed)
	invalidRaw := []string{"127.0.0.1", "not-a-valid-ip"}
	if _, err := parsePermittedIPs(invalidRaw); err == nil {
		t.Fatalf("expected error on invalid IP string, got nil")
	}
}

func TestCACliInit_BroadDomainRequirement(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	// Broad domain .local without --allow-broad-domains must fail closed
	outBuf, errBuf := setupTest()
	rootCmd.SetArgs([]string{"ca", "init", "--permitted-dns", ".local"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatalf("expected ca init to fail without --allow-broad-domains for .local, out=%s, err=%s", outBuf.String(), errBuf.String())
	}

	// Broad domain with --allow-broad-domains succeeds
	outBuf, errBuf = setupTest()
	rootCmd.SetArgs([]string{"ca", "init", "--permitted-dns", ".local", "--allow-broad-domains"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("expected ca init to succeed with --allow-broad-domains, got: %v, err=%s", err, errBuf.String())
	}
}

func TestCACliDeriveBridgeToken(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	caDir := filepath.Join(tempHome, ".locksmith", "ca")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		t.Fatal(err)
	}

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 1)
	}
	keyPath := filepath.Join(caDir, "bridge.key")
	if err := os.WriteFile(keyPath, masterKey, 0600); err != nil {
		t.Fatal(err)
	}

	deriver, _ := spiffe.NewBridgeTokenDeriver(masterKey)
	expectedToken := deriver.DeriveToken(4)

	outBuf, errBuf := setupTest()
	rootCmd.SetArgs([]string{"ca", "derive-bridge-token", "--cid", "4", "--ca-dir", caDir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("ca derive-bridge-token failed: %v, err: %s", err, errBuf.String())
	}

	derivedOutput := strings.TrimSpace(outBuf.String())
	if derivedOutput != expectedToken {
		t.Fatalf("expected token %q, got %q", expectedToken, derivedOutput)
	}

	// Test CID < 3 rejected
	outBuf, errBuf = setupTest()
	rootCmd.SetArgs([]string{"ca", "derive-bridge-token", "--cid", "2", "--ca-dir", caDir})
	if err := rootCmd.Execute(); err == nil {
		t.Fatalf("expected CID 2 to be rejected, got success with token %q", outBuf.String())
	}
}

func TestCACliInit_TrustValidationFailsClosed(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	// ca init --trust with invalid supernet CIDR must fail closed
	outBuf, errBuf := setupTest()
	rootCmd.SetArgs([]string{"ca", "init", "--trust", "--permitted-ip", "0.0.0.0/0"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatalf("expected ca init --trust with 0.0.0.0/0 to fail closed, out=%s, err=%s", outBuf.String(), errBuf.String())
	}

	// ca init --trust with public IP range must fail closed
	outBuf, errBuf = setupTest()
	rootCmd.SetArgs([]string{"ca", "init", "--trust", "--permitted-ip", "8.8.8.0/24"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatalf("expected ca init --trust with 8.8.8.0/24 to fail closed, out=%s, err=%s", outBuf.String(), errBuf.String())
	}
}

func TestCACliDeriveBridgeToken_FromKeychain(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	caDir := filepath.Join(tempHome, ".locksmith", "ca")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		t.Fatal(err)
	}

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 10)
	}

	deriver, _ := spiffe.NewBridgeTokenDeriver(masterKey)
	expectedToken := deriver.DeriveToken(5)

	outBuf, errBuf := setupTest()
	// Pre-seed mock keychain with secretBridgeKey
	_ = ls.SetWithContext(secretBridgeKey, masterKey, time.Now().Add(time.Hour), false, "token", "locksmith-spiffe", "", nil)

	// derive-bridge-token without a disk key file must succeed via keychain
	rootCmd.SetArgs([]string{"ca", "derive-bridge-token", "--cid", "5", "--ca-dir", caDir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("expected ca derive-bridge-token from keychain to succeed: %v, err: %s", err, errBuf.String())
	}

	derivedOutput := strings.TrimSpace(outBuf.String())
	if derivedOutput != expectedToken {
		t.Fatalf("expected token %q, got %q", expectedToken, derivedOutput)
	}
}
