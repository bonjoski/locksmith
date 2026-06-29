package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

type mockSyncCLIBackend struct {
	secrets map[string][]byte
}

func (m *mockSyncCLIBackend) Set(service, account string, data []byte, requireBiometrics bool) error {
	m.secrets[account] = data
	return nil
}

func (m *mockSyncCLIBackend) Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	data, ok := m.secrets[account]
	if !ok {
		return nil, fmt.Errorf("secret not found")
	}
	return data, nil
}

func (m *mockSyncCLIBackend) Delete(service, account string, useBiometrics bool, prompt string) error {
	delete(m.secrets, account)
	return nil
}

func (m *mockSyncCLIBackend) List(service string, useBiometrics bool, prompt string) ([]string, error) {
	var keys []string
	for k := range m.secrets {
		keys = append(keys, k)
	}
	return keys, nil
}

func TestSyncCommands(t *testing.T) {
	_, _ = setupTest()

	mb := &mockSyncCLIBackend{secrets: make(map[string][]byte)}
	ls.Backend = mb

	s1 := locksmith.Secret{Value: []byte("val1"), CreatedAt: time.Now().Add(-10 * time.Minute), ExpiresAt: time.Now().Add(time.Hour)}
	s2 := locksmith.Secret{Value: []byte("val2"), CreatedAt: time.Now().Add(-5 * time.Minute), ExpiresAt: time.Now().Add(time.Hour)}
	_ = ls.ImportSecret("key1", s1, false)
	_ = ls.ImportSecret("key2", s2, false)

	tmpDir, err := os.MkdirTemp("", "locksmith-cli-sync-test-*")
	if err != nil {
		t.Fatalf("Failed to create tmp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	outFile := filepath.Join(tmpDir, "sync.enc")
	passphrase := "test-sync-passphrase"

	// 2. Test sync export command
	rootCmd.SetArgs([]string{"sync", "export", "--file", outFile, "--passphrase", passphrase})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("Execute 'sync export' failed: %v", err)
	}

	if _, err := os.Stat(outFile); err != nil {
		t.Fatalf("Encrypted export file was not created: %v", err)
	}

	// 3. Test sync import command
	_, _ = setupTest()
	mbDest := &mockSyncCLIBackend{secrets: make(map[string][]byte)}
	ls.Backend = mbDest

	rootCmd.SetArgs([]string{"sync", "import", "--file", outFile, "--passphrase", passphrase, "--policy", "overwrite"})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("Execute 'sync import' failed: %v", err)
	}

	importedS1, err := ls.Get("key1")
	if err != nil || string(importedS1) != "val1" {
		t.Errorf("Expected key1 to contain 'val1', got error: %v", err)
	}

	importedS2, err := ls.Get("key2")
	if err != nil || string(importedS2) != "val2" {
		t.Errorf("Expected key2 to contain 'val2', got error: %v", err)
	}
}

func TestSyncCommandsPromptInput(t *testing.T) {
	_, _ = setupTest()
	mb := &mockSyncCLIBackend{secrets: make(map[string][]byte)}
	ls.Backend = mb

	s1 := locksmith.Secret{Value: []byte("val1"), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	_ = ls.ImportSecret("key1", s1, false)

	tmpDir, err := os.MkdirTemp("", "locksmith-cli-sync-prompt-test-*")
	if err != nil {
		t.Fatalf("Failed to create tmp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	outFile := filepath.Join(tmpDir, "sync.enc")

	rootCmd.SetIn(strings.NewReader("prompted-passphrase\n"))
	rootCmd.SetArgs([]string{"sync", "export", "--file", outFile})

	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("Execute 'sync export' with prompt failed: %v", err)
	}

	_, _ = setupTest()
	mbDest := &mockSyncCLIBackend{secrets: make(map[string][]byte)}
	ls.Backend = mbDest

	rootCmd.SetIn(strings.NewReader("prompted-passphrase\n"))
	rootCmd.SetArgs([]string{"sync", "import", "--file", outFile})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("Execute 'sync import' with prompt failed: %v", err)
	}

	importedS1, err := ls.Get("key1")
	if err != nil || string(importedS1) != "val1" {
		t.Errorf("Expected key1 to contain 'val1', got error: %v", err)
	}
}
