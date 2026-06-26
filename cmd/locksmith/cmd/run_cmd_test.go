package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

func TestRunCommandArgs(t *testing.T) {
	_, _ = setupTest()

	// 1. Test running with no arguments (should fail)
	rootCmd.SetArgs([]string{"run"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("Expected error when running without command arguments, got nil")
	}
}

func TestRunCommandSuccess(t *testing.T) {
	_, _ = setupTest()

	// Mock exitFunc to capture the exit code
	var capturedExitCode int
	originalExitFunc := exitFunc
	exitFunc = func(code int) {
		capturedExitCode = code
	}
	defer func() { exitFunc = originalExitFunc }()

	// Add a dummy secret
	mc := ls.Cache.(*mockCache)
	mc.secrets["test/key"] = locksmith.Secret{
		Value:     []byte("my-secret-val"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	// We also need to seed the backend mock in case of a cache miss (setupTest resets this)
	mb := &mockRunBackend{
		secrets: make(map[string][]byte),
	}
	sec := locksmith.Secret{
		Value:     []byte("my-secret-val"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	secData, _ := json.Marshal(sec)
	mb.secrets["test/key"] = secData
	ls.Backend = mb

	// Set an environment variable with locksmith prefix
	os.Setenv("TEST_RUN_VAR", "locksmith://test/key")
	defer os.Unsetenv("TEST_RUN_VAR")

	// Create a temporary env file
	tmpDir, err := os.MkdirTemp("", "locksmith-run-test-*")
	if err != nil {
		t.Fatalf("Failed to create tmp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	envPath := filepath.Join(tmpDir, ".env")
	err = os.WriteFile(envPath, []byte("LOCKSMITH_SECRET_TEST_FILE_VAR=test/key"), 0644)
	if err != nil {
		t.Fatalf("Failed to write env file: %v", err)
	}

	// Execute 'locksmith run --env-file <path> -- true' (or 'true' depending on platform)
	// 'true' exists on macOS and Linux.
	rootCmd.SetArgs([]string{"run", "--env-file", envPath, "--", "true"})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("run command execution failed: %v", err)
	}

	if capturedExitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", capturedExitCode)
	}
}

type mockRunBackend struct {
	secrets map[string][]byte
}

func (m *mockRunBackend) Set(service, account string, data []byte, requireBiometrics bool) error {
	return nil
}

func (m *mockRunBackend) Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	return m.secrets[account], nil
}

func (m *mockRunBackend) Delete(service, account string, useBiometrics bool, prompt string) error {
	return nil
}

func (m *mockRunBackend) List(service string, useBiometrics bool, prompt string) ([]string, error) {
	return []string{}, nil
}
