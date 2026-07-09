package cmd

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith" // #nosec G101
)

// mockCache for CLI tests
type mockCache struct {
	secrets map[string]locksmith.Secret
}

func (m *mockCache) Set(key string, secret locksmith.Secret, ttl time.Duration) error {
	// Copy value to avoid zeroing issues in tests
	val := make([]byte, len(secret.Value))
	copy(val, secret.Value)
	secret.Value = val
	m.secrets[key] = secret
	return nil
}

func (m *mockCache) Get(key string) (*locksmith.Secret, error) {
	s, ok := m.secrets[key]
	if !ok {
		return nil, fmt.Errorf("cache miss")
	}
	return &s, nil
}

func (m *mockCache) Delete(key string) error {
	delete(m.secrets, key)
	return nil
}

func (m *mockCache) IsExpired(key string, ttl time.Duration) bool {
	return false
}

// mockBackend for CLI tests to avoid native keyring dependencies
type mockBackend struct{}

func (m *mockBackend) Set(service, account string, data []byte, requireBiometrics bool) error {
	return nil
}

func (m *mockBackend) Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	return []byte("{\"value\":null,\"created_at\":\"0001-01-01T00:00:00Z\",\"expires_at\":\"0001-01-01T00:00:00Z\"}"), nil
}

func (m *mockBackend) Delete(service, account string, useBiometrics bool, prompt string) error {
	return nil
}

func (m *mockBackend) List(service string, useBiometrics bool, prompt string) ([]string, error) {
	return []string{}, nil
}

func setupTest() (*bytes.Buffer, *bytes.Buffer) {
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)

	// Reset global state
	jsonOutput = false
	noNewline = false

	cfg = &locksmith.Config{
		Auth: locksmith.AuthConfig{RequireBiometrics: false},
		Notifications: locksmith.NotificationConfig{
			ExpiringThreshold: "7d",
			ShowOnGet:         false,
		},
	}

	// Inject a mock locksmith instance with an empty cache and mock backend
	mc := &mockCache{secrets: make(map[string]locksmith.Secret)}

	// Pre-seed a test key so it doesn't query the native keychain on a cache miss
	mc.secrets["nonexistent_test_key_xyz123"] = locksmith.Secret{
		Value:     []byte("test-data"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour * 24),
	}

	ls = locksmith.NewWithCache(mc)
	ls.Config = cfg
	ls.Backend = &mockBackend{} // Inject mock backend to avoid native calls
	ls.Options.RequireBiometrics = false

	rootCmd.SetOut(outBuf)
	rootCmd.SetErr(errBuf)
	rootCmd.SetIn(new(bytes.Buffer)) // Default empty input

	return outBuf, errBuf
}

func TestRootCommand(t *testing.T) {
	outBuf, _ := setupTest()
	rootCmd.SetArgs([]string{"--version"})

	// We just want to ensure Execute doesn't panic on a basic flag
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Root command execution failed: %v", err)
	}

	if !strings.Contains(outBuf.String(), locksmith.Version) {
		t.Errorf("Expected version %s in output, got %s", locksmith.Version, outBuf.String())
	}
}

func TestGetCommandFlags(t *testing.T) {
	_, _ = setupTest()

	// Test --no-newline flag parsing
	rootCmd.SetArgs([]string{"get", "nonexistent_test_key_xyz123", "--no-newline"})

	// The test key now exists in the mock cache, so we expect execution to SUCCEED
	err := rootCmd.Execute()

	if err != nil {
		t.Errorf("Expected execution to succeed on preset mock key, but it failed: %v", err)
	}

	if !noNewline {
		t.Error("Expected noNewline flag to be set to true")
	}

	_, _ = setupTest() // reset

	// Test --json flag parsing
	rootCmd.SetArgs([]string{"get", "nonexistent_test_key_xyz123", "--json"})
	_ = rootCmd.Execute()

	if !jsonOutput {
		t.Error("Expected jsonOutput flag to be set to true")
	}
}

func TestTokenSubcommand(t *testing.T) {
	_, _ = setupTest()

	// Verify token get aliases to the get command
	rootCmd.SetArgs([]string{"token", "get", "nonexistent_test_key_xyz123", "-n"})
	_ = rootCmd.Execute()

	if !noNewline {
		t.Error("Expected -n flag to correctly map to noNewline flag under the token subcommand")
	}
}

func TestAddCommand(t *testing.T) {
	outBuf, _ := setupTest()

	// 1. Test adding with 2 required arguments
	key := "test-add-arg"
	secret := "secret-value"
	rootCmd.SetArgs([]string{"add", key, secret})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Add command failed: %v", err)
	}

	// Verify it was saved in the mock cache
	mc := ls.Cache.(*mockCache)
	s, ok := mc.secrets[key]
	if !ok {
		t.Errorf("Expected secret '%s' to be saved", key)
	}
	if string(s.Value) != secret {
		t.Errorf("Expected secret value '%s', got '%s'", secret, string(s.Value))
	}

	if !strings.Contains(outBuf.String(), "Successfully saved secret") {
		t.Errorf("Expected success message, got: %s", outBuf.String())
	}

	// 2. Test that 1 argument fails (secret required)
	_, _ = setupTest()
	rootCmd.SetArgs([]string{"add", "prompt-key"})
	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("Expected add command to fail when secret argument is missing")
	}

	// 3. Test that 0 arguments fails (key and secret required)
	_, _ = setupTest()
	rootCmd.SetArgs([]string{"add"})
	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("Expected add command to fail when key and secret arguments are missing")
	}
}
