//go:build locksmith_test_harness

package cmd

import (
	"testing"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

// In test harness builds, initTestHarnessLocksmith activates MockBackend when LOCKSMITH_MOCK_BACKEND=1.
func TestAdversarial_TestHarnessActivationInHarnessBuild(t *testing.T) {
	t.Setenv("LOCKSMITH_MOCK_BACKEND", "1")
	cfg := &locksmith.Config{
		Auth: locksmith.AuthConfig{RequireBiometrics: true},
	}
	if !initTestHarnessLocksmith(cfg) {
		t.Fatalf("Expected initTestHarnessLocksmith to return true in test harness build with LOCKSMITH_MOCK_BACKEND=1")
	}
}
