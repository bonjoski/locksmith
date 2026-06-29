package locksmith

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/native"
)

type mockBackend struct{}

func (m *mockBackend) Set(service, account string, data []byte, requireBiometrics bool) error {
	return nil
}

func (m *mockBackend) Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	return nil, nil
}

func (m *mockBackend) Delete(service, account string, useBiometrics bool, prompt string) error {
	return nil
}

func (m *mockBackend) List(service string, useBiometrics bool, prompt string) ([]string, error) {
	return []string{}, nil
}

func setupAccessControlTest(t *testing.T, yamlConfig string) (*Locksmith, *MockCache, string, func()) {
	tempDir, err := os.MkdirTemp("", "locksmith-test-home")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	locksmithDir := filepath.Join(tempDir, ".locksmith")
	if err := os.MkdirAll(locksmithDir, 0700); err != nil {
		t.Fatalf("Failed to create .locksmith dir: %v", err)
	}

	configPath := filepath.Join(locksmithDir, "config.yml")
	if err := os.WriteFile(configPath, []byte(yamlConfig), 0600); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	oldHome := os.Getenv("HOME")
	oldUserProfile := os.Getenv("USERPROFILE")
	os.Setenv("HOME", tempDir)
	os.Setenv("USERPROFILE", tempDir)

	cleanup := func() {
		os.Setenv("HOME", oldHome)
		os.Setenv("USERPROFILE", oldUserProfile)
		os.RemoveAll(tempDir)
	}

	mc := &MockCache{secrets: make(map[string]Secret)}
	ls := NewWithCache(mc)
	ls.Backend = &mockBackend{}
	ls.Options.RequireBiometrics = false

	return ls, mc, tempDir, cleanup
}

func TestAccessControlDeny(t *testing.T) {
	yamlConfig := `
access_control:
  - secret: "aws/*"
    allowed_apps:
      - path: "/usr/bin/false"
`
	ls, mc, _, cleanup := setupAccessControlTest(t, yamlConfig)
	defer cleanup()

	// Pre-seed mock cache
	mc.secrets["aws/key"] = Secret{
		Value:     []byte("my-aws-secret"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	// Attempting to read "aws/key" should fail because the calling process (the test binary) is NOT "/usr/bin/false"
	val, err := ls.Get("aws/key")
	if err == nil {
		t.Fatalf("Expected access control error, but got value: %s", val)
	}

	if !strings.Contains(err.Error(), "security: access denied") {
		t.Errorf("Expected access denied error message, got: %v", err)
	}
}

func TestAccessControlAllow(t *testing.T) {
	// Find out current calling process path so we can whitelist it dynamically
	caller, err := native.GetCallingProcessInfo()
	if err != nil {
		t.Fatalf("Failed to resolve caller process path: %v", err)
	}

	yamlConfig := fmt.Sprintf(`
access_control:
  - secret: "aws/*"
    allowed_apps:
      - path: "%s"
`, strings.ReplaceAll(caller.Path, "\\", "\\\\")) // Escape backslashes for Windows

	ls, mc, _, cleanup := setupAccessControlTest(t, yamlConfig)
	defer cleanup()

	// Pre-seed mock cache
	mc.secrets["aws/key"] = Secret{
		Value:     []byte("my-aws-secret"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	// This should succeed because the test runner process is explicitly whitelisted
	val, err := ls.Get("aws/key")
	if err != nil {
		t.Fatalf("Expected successful access, got error: %v", err)
	}

	if !bytes.Equal(val, []byte("my-aws-secret")) {
		t.Errorf("Expected 'my-aws-secret', got '%s'", val)
	}
}

func TestAccessControlNoRule(t *testing.T) {
	// If no rule matches the secret, access should be allowed by default (backwards compatibility)
	yamlConfig := `
access_control:
  - secret: "aws/*"
    allowed_apps:
      - path: "/usr/bin/false"
`
	ls, mc, _, cleanup := setupAccessControlTest(t, yamlConfig)
	defer cleanup()

	// Pre-seed mock cache
	mc.secrets["other/secret"] = Secret{
		Value:     []byte("other-secret-value"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	// This should succeed because no rule matches "other/secret"
	val, err := ls.Get("other/secret")
	if err != nil {
		t.Fatalf("Expected successful access, got error: %v", err)
	}

	if !bytes.Equal(val, []byte("other-secret-value")) {
		t.Errorf("Expected 'other-secret-value', got '%s'", val)
	}
}

func TestAccessControlDefaultPolicyDeny(t *testing.T) {
	yamlConfig := `
auth:
  default_policy: deny
`
	ls, mc, _, cleanup := setupAccessControlTest(t, yamlConfig)
	defer cleanup()

	mc.secrets["some/key"] = Secret{
		Value: []byte("secret-val"),
	}

	// Should fail because default_policy is deny and no explicit rule allows it
	_, err := ls.Get("some/key")
	if err == nil {
		t.Fatal("Expected access denied under Zero-Trust policy, but got none")
	}

	if !strings.Contains(err.Error(), "Zero-Trust policy (default_policy: deny) is active") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestAccessControlDefaultPolicyDenyWithAllow(t *testing.T) {
	caller, err := native.GetCallingProcessInfo()
	if err != nil {
		t.Fatalf("Failed to resolve caller process path: %v", err)
	}

	yamlConfig := fmt.Sprintf(`
auth:
  default_policy: deny
access_control:
  - secret: "aws/*"
    allowed_apps:
      - path: "%s"
`, strings.ReplaceAll(caller.Path, "\\", "\\\\"))

	ls, mc, _, cleanup := setupAccessControlTest(t, yamlConfig)
	defer cleanup()

	mc.secrets["aws/key"] = Secret{
		Value: []byte("aws-val"),
	}
	mc.secrets["other/key"] = Secret{
		Value: []byte("other-val"),
	}

	// 1. Should succeed for "aws/key" because it matches the whitelist rule
	val, err := ls.Get("aws/key")
	if err != nil {
		t.Fatalf("Expected successful access to aws/key, got: %v", err)
	}
	if !bytes.Equal(val, []byte("aws-val")) {
		t.Errorf("Expected 'aws-val', got %s", val)
	}

	// 2. Should fail for "other/key" because it doesn't match any whitelist rule
	_, err = ls.Get("other/key")
	if err == nil {
		t.Fatal("Expected access denied for other/key under Zero-Trust, but got none")
	}
}

func TestConfigFilePermissionsAutoRepair(t *testing.T) {
	// Only run on non-Windows platforms
	if os.PathSeparator == '\\' {
		t.Skip("Skipping unix file permissions test on Windows")
	}

	yamlConfig := `
auth:
  require_biometrics: false
`
	_, _, tempHome, cleanup := setupAccessControlTest(t, yamlConfig)
	defer cleanup()

	configPath := filepath.Join(tempHome, ".locksmith", "config.yml")
	err := os.Chmod(configPath, 0644)
	if err != nil {
		t.Fatalf("Failed to chmod config file: %v", err)
	}

	// Loading locksmith (or loading config) should trigger auto-repair
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed during auto-repair check: %v", err)
	}
	if cfg == nil {
		t.Fatal("Expected non-nil config")
	}

	// Verify that the permissions on disk have been repaired to 0600
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("Failed to stat config file: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("Expected file permissions to be auto-repaired to 0600, but got %04o", perm)
	}
}
