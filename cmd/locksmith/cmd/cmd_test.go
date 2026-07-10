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
type mockBackend struct {
	cache    *mockCache
	getCalls int
}

func (m *mockBackend) Set(service, account string, data []byte, requireBiometrics bool) error {
	return nil
}

func (m *mockBackend) Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	m.getCalls++
	return []byte("{\"value\":null,\"created_at\":\"0001-01-01T00:00:00Z\",\"expires_at\":\"0001-01-01T00:00:00Z\"}"), nil
}

func (m *mockBackend) Delete(service, account string, useBiometrics bool, prompt string) error {
	return nil
}

func (m *mockBackend) List(service string, useBiometrics bool, prompt string) ([]string, error) {
	if m.cache == nil {
		return []string{}, nil
	}

	keys := make([]string, 0, len(m.cache.secrets))
	for key := range m.cache.secrets {
		keys = append(keys, key)
	}

	return keys, nil
}

func setupTest() (*bytes.Buffer, *bytes.Buffer) {
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)

	// Reset global state
	jsonOutput = false
	noNewline = false
	listDetails = false
	secretType = ""
	ownerApplication = ""
	sourceURL = ""

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
	ls.Backend = &mockBackend{cache: mc} // Inject mock backend to avoid native calls
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

	runAddAndAssertSaved(t, outBuf, []string{"add", "test-add-arg", "secret-value"}, "", "test-add-arg", "secret-value", true)

	// 2. Test that 1 argument prompts for missing secret
	outBuf, _ = setupTest()
	runAddAndAssertSaved(t, outBuf, []string{"add", "prompt-key"}, "prompt-secret\n\n\n\n", "prompt-key", "prompt-secret", false)
	assertAddPrompts(t, outBuf, false)

	// 3. Test that 0 arguments prompts for key and secret
	outBuf, _ = setupTest()
	runAddAndAssertSaved(t, outBuf, []string{"add"}, "interactive-key\ninteractive-secret\n\n\n\n", "interactive-key", "interactive-secret", false)
	assertAddPrompts(t, outBuf, true)
}

func runAddAndAssertSaved(t *testing.T, outBuf *bytes.Buffer, args []string, stdin string, key string, secret string, assertSuccessMsg bool) {
	t.Helper()

	if stdin != "" {
		rootCmd.SetIn(bytes.NewBufferString(stdin))
	}
	rootCmd.SetArgs(args)

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Add command failed: %v", err)
	}

	mc := ls.Cache.(*mockCache)
	s, ok := mc.secrets[key]
	if !ok {
		t.Fatalf("Expected secret '%s' to be saved", key)
	}
	if string(s.Value) != secret {
		t.Fatalf("Expected secret value '%s', got '%s'", secret, string(s.Value))
	}

	if assertSuccessMsg {
		if !strings.Contains(outBuf.String(), "Successfully saved secret") {
			t.Fatalf("Expected success message, got: %s", outBuf.String())
		}
	}
}

func assertAddPrompts(t *testing.T, outBuf *bytes.Buffer, expectKeyPrompt bool) {
	t.Helper()

	output := outBuf.String()
	if expectKeyPrompt {
		if !strings.Contains(output, "Key: ") {
			t.Fatalf("Expected prompt output to contain 'Key: ', got: %s", output)
		}
	}
	if !strings.Contains(output, "Secret: ") {
		t.Fatalf("Expected prompt output to contain 'Secret: ', got: %s", output)
	}
	if !strings.Contains(output, "Secret type (optional") {
		t.Fatalf("Expected prompt output to contain optional secret type prompt, got: %s", output)
	}
	if !strings.Contains(output, "Owner app (optional") {
		t.Fatalf("Expected prompt output to contain optional owner app prompt, got: %s", output)
	}
	if !strings.Contains(output, "Source URL (optional)") {
		t.Fatalf("Expected prompt output to contain optional source URL prompt, got: %s", output)
	}
}

func TestListCommand(t *testing.T) {
	outBuf, _ := setupTest()
	rootCmd.SetArgs([]string{"list"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("List command failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "KEY") {
		t.Fatalf("Expected list output to contain table header, got: %s", output)
	}
	if !strings.Contains(output, "nonexistent_test_key_xyz123") {
		t.Fatalf("Expected list output to contain seeded key, got: %s", output)
	}
}

func TestListCommandDetails(t *testing.T) {
	outBuf, _ := setupTest()

	err := ls.SetWithContext(
		"details-key",
		[]byte("details-secret"),
		time.Now().Add(24*time.Hour),
		false,
		locksmith.SecretTypeOAuthToken,
		"github",
		"https://api.github.com/app/installations/123/access_tokens",
		map[string]string{
			"environment":            "ci",
			"github_app_private_key": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
		},
	)
	if err != nil {
		t.Fatalf("Failed to seed metadata-rich secret: %v", err)
	}

	rootCmd.SetArgs([]string{"list", "--details"})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("List --details command failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "Key:        details-key") {
		t.Fatalf("Expected details output to contain key, got: %s", output)
	}
	if !strings.Contains(output, "Type:       oauth_token") {
		t.Fatalf("Expected details output to contain secret type, got: %s", output)
	}
	if !strings.Contains(output, "Owner App:  github") {
		t.Fatalf("Expected details output to contain owner application, got: %s", output)
	}
	if !strings.Contains(output, "Source URL: https://api.github.com/app/installations/123/access_tokens") {
		t.Fatalf("Expected details output to contain source URL, got: %s", output)
	}
	if !strings.Contains(output, "Metadata:") || !strings.Contains(output, "  environment: ci") {
		t.Fatalf("Expected details output to contain metadata map, got: %s", output)
	}
	if !strings.Contains(output, "  github_app_private_key: [REDACTED]") {
		t.Fatalf("Expected sensitive metadata to be redacted, got: %s", output)
	}

	mb, ok := ls.Backend.(*mockBackend)
	if !ok {
		t.Fatalf("Expected mock backend type assertion to succeed")
	}
	if mb.getCalls != 0 {
		t.Fatalf("Expected list --details to avoid per-key backend reads, but Get was called %d times", mb.getCalls)
	}
}
