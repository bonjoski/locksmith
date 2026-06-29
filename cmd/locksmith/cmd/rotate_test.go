//go:build locksmith_admin

package cmd

import (
	"encoding/json"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

type mockRotateCLIBackend struct {
	secrets map[string][]byte
}

func (m *mockRotateCLIBackend) Set(service, account string, data []byte, requireBiometrics bool) error {
	m.secrets[account] = data
	return nil
}

func (m *mockRotateCLIBackend) Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	data, ok := m.secrets[account]
	if !ok {
		return nil, fmt.Errorf("secret not found")
	}
	return data, nil
}

func (m *mockRotateCLIBackend) Delete(service, account string, useBiometrics bool, prompt string) error {
	delete(m.secrets, account)
	return nil
}

func (m *mockRotateCLIBackend) List(service string, useBiometrics bool, prompt string) ([]string, error) {
	var keys []string
	for k := range m.secrets {
		keys = append(keys, k)
	}
	return keys, nil
}

func TestCLIRotateCommand(t *testing.T) {
	_, _ = setupTest()
	rotateAll = false // Reset global flag state to prevent test pollution

	mb := &mockRotateCLIBackend{secrets: make(map[string][]byte)}
	ls.Backend = mb

	// 1. Seed secrets
	now := time.Now()
	expiredSecret := locksmith.Secret{
		Value:     []byte("old-expired-val"),
		CreatedAt: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-1 * time.Hour),
	}
	validSecret := locksmith.Secret{
		Value:     []byte("valid-val"),
		CreatedAt: now,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
	}

	expBytes, _ := json.Marshal(expiredSecret)
	valBytes, _ := json.Marshal(validSecret)
	mb.secrets["db/expired-key"] = expBytes
	mb.secrets["db/valid-key"] = valBytes

	// Cache seeding
	_ = ls.Cache.Set("db/expired-key", expiredSecret, time.Hour)
	_ = ls.Cache.Set("db/valid-key", validSecret, time.Hour)

	// Configure rotation rules
	var targetCommand string
	if runtime.GOOS == "windows" {
		targetCommand = `echo cli-rotated-value & rem`
	} else {
		targetCommand = `echo "cli-rotated-value"`
	}

	cfg.Rotation = []locksmith.RotationRule{
		{
			Secret:     "db/*",
			HookType:   "script",
			HookTarget: targetCommand,
			Timeout:    "5s",
		},
	}

	// 2. Execute rotate --all
	rootCmd.SetArgs([]string{"rotate", "--all"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Execute 'rotate --all' failed: %v", err)
	}

	// Verify expired key was rotated
	rotatedVal, err := ls.Get("db/expired-key")
	if err != nil || string(rotatedVal) != "cli-rotated-value" {
		t.Errorf("Expected rotated value 'cli-rotated-value', got '%s' (err: %v)", rotatedVal, err)
	}

	// Verify valid key was skipped
	validVal, err := ls.Get("db/valid-key")
	if err != nil || string(validVal) != "valid-val" {
		t.Errorf("Expected valid key to remain 'valid-val', got '%s'", validVal)
	}

	// 3. Force rotate a specific key
	rootCmd.SetArgs([]string{"rotate", "db/valid-key"})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("Execute 'rotate db/valid-key' failed: %v", err)
	}

	// Verify valid key is now rotated
	forcedVal, err := ls.Get("db/valid-key")
	if err != nil || string(forcedVal) != "cli-rotated-value" {
		t.Errorf("Expected valid key to be rotated to 'cli-rotated-value', got '%s'", forcedVal)
	}
}

func TestCLIRotateCommandNoArgsError(t *testing.T) {
	_, _ = setupTest()
	rotateAll = false // Reset global flag state to prevent test pollution

	// Should return error if no key and no --all flag is passed
	rootCmd.SetArgs([]string{"rotate"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("Expected rotate command to fail without args or --all flag, but it succeeded")
	}
}
