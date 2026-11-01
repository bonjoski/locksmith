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

	// 1. Test ca init
	outBuf, errBuf := setupTest()
	rootCmd.SetArgs([]string{"ca", "init", "--days", "30"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("ca init failed: %v, output: %s %s", err, outBuf.String(), errBuf.String())
	}

	if !strings.Contains(outBuf.String(), "Successfully initialized Sovereign Dual-Root CA") {
		t.Errorf("unexpected output from ca init: %s", outBuf.String())
	}

	rootCertPath := filepath.Join(tempHome, ".locksmith", "ca", "root-ca.crt")
	if _, err := os.Stat(rootCertPath); os.IsNotExist(err) {
		t.Fatalf("expected root-ca.crt to exist at %s", rootCertPath)
	}

	rootPQCCertPath := filepath.Join(tempHome, ".locksmith", "ca", "root-ca-pqc.crt")
	if _, err := os.Stat(rootPQCCertPath); os.IsNotExist(err) {
		t.Fatalf("expected root-ca-pqc.crt to exist at %s", rootPQCCertPath)
	}

	rootDualCertPath := filepath.Join(tempHome, ".locksmith", "ca", "root-ca-dual.crt")
	if _, err := os.Stat(rootDualCertPath); os.IsNotExist(err) {
		t.Fatalf("expected root-ca-dual.crt to exist at %s", rootDualCertPath)
	}

	// 2. Test ca status
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

	// 3. Test ca issue server
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

	// 4. Test ca issue client
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
