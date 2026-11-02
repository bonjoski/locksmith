package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCACliCommands(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	testCACliInit(t, tempHome)
	testCACliStatus(t)
	testCACliIssueServer(t, tempHome)
	testCACliIssueClient(t, tempHome)
	testCACliIssueSPIFFE(t, tempHome)
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
