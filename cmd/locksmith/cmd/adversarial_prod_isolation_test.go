//go:build !locksmith_test_harness

package cmd

import (
	"testing"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

// ADV-FINAL-06: Production Binary Test Harness Isolation Probe
// An attacker sets LOCKSMITH_MOCK_BACKEND=1 in the environment hoping to trigger an in-memory mock
// and bypass hardware enclave / Touch ID biometric authentication in production.
func TestAdversarial_TestHarnessIsolationInProduction(t *testing.T) {
	t.Setenv("LOCKSMITH_MOCK_BACKEND", "1")
	// In builds without the locksmith_test_harness tag, initTestHarnessLocksmith returns false
	// and never initializes MockBackend or bypasses biometrics.
	cfg := &locksmith.Config{
		Auth: locksmith.AuthConfig{RequireBiometrics: true},
	}
	if initTestHarnessLocksmith(cfg) {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: initTestHarnessLocksmith returned true in build without locksmith_test_harness tag! Production binary contains active test hook backdoor.")
	}
}
