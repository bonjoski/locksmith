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

func setupAccessControlTest(t *testing.T, yamlConfig string) (*Locksmith, *MockCache, string) {
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

	mc := &MockCache{secrets: make(map[string]Secret)}
	ls := NewWithCache(mc)
	ls.Backend = &mockBackend{}
	ls.Options.RequireBiometrics = false

	return ls, mc, tempDir
}

func TestAccessControlDeny(t *testing.T) {
	yamlConfig := `
access_control:
  - secret: "aws/*"
    allowed_apps:
      - path: "/usr/bin/false"
`
	ls, mc, tempHome := setupAccessControlTest(t, yamlConfig)
	defer os.RemoveAll(tempHome)

	// Mock HOME
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", oldHome)

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

	ls, mc, tempHome := setupAccessControlTest(t, yamlConfig)
	defer os.RemoveAll(tempHome)

	// Mock HOME
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", oldHome)

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
	ls, mc, tempHome := setupAccessControlTest(t, yamlConfig)
	defer os.RemoveAll(tempHome)

	// Mock HOME
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", oldHome)

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
