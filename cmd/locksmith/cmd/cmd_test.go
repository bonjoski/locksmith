package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

// mockCache for CLI tests
type mockCache struct {
	secrets map[string]locksmith.Secret
}

func (m *mockCache) Set(key string, secret locksmith.Secret, ttl time.Duration) error {
	m.secrets[key] = secret
	return nil
}

func (m *mockCache) Get(key string) (*locksmith.Secret, error) {
	s, ok := m.secrets[key]
	if !ok {
		return nil, nil // Return nil, nil when not found in cache (simulating pass-through to native)
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

func setupTest() (*bytes.Buffer, *bytes.Buffer) {
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)

	// Reset global state
	jsonOutput = false
	noNewline = false
	allowNoBiometrics = true // satisfy the guard rail since we inject tests with disabled biometrics

	cfg = &locksmith.Config{
		Auth: locksmith.AuthConfig{RequireBiometrics: false},
		Notifications: locksmith.NotificationConfig{
			ExpiringThreshold: "7d",
			ShowOnGet:         false,
		},
	}

	// Inject a mock locksmith instance with an empty cache to avoid native calls in basic routing tests
	mc := &mockCache{secrets: make(map[string]locksmith.Secret)}

	// Pre-seed a test key so it doesn't query the native keychain on a cache miss
	mc.secrets["nonexistent_test_key_xyz123"] = locksmith.Secret{
		Value:     []byte("test-data"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour * 24),
	}

	ls = locksmith.NewWithCache(mc)
	ls.Options.RequireBiometrics = false

	rootCmd.SetOut(outBuf)
	rootCmd.SetErr(errBuf)

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
