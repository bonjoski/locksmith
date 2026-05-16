//go:build locksmith_admin && darwin
// +build locksmith_admin,darwin

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

func TestSummonE2E(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("Skipping local E2E integration test in CI environment")
	}

	testSecretID := "test-summon-e2e-secret-key"
	testSecretVal := "super-secure-local-summon-token-value-123!"

	// 1. Initialize locksmith with biometrics enabled for secure E2E access
	opts := locksmith.Options{
		RequireBiometrics: true,
		BypassCache:       true,
	}
	ls, err := locksmith.NewWithOptions(opts)
	if err != nil {
		t.Fatalf("Failed to initialize locksmith: %v", err)
	}

	t.Log("Note: Running E2E test. Biometric authentication (Touch ID / Apple Watch) is required!")

	// Clean up any residual test key from previous runs
	_ = ls.Delete(testSecretID)

	// 2. Store the test secret requiring biometrics
	expiresAt := time.Now().Add(1 * time.Hour)
	err = ls.SetWithBiometrics(testSecretID, []byte(testSecretVal), expiresAt, true)
	if err != nil {
		t.Fatalf("Failed to write test secret to Keychain: %v", err)
	}

	// Ensure cleanup at the end of the test
	defer func() {
		err := ls.Delete(testSecretID)
		if err != nil {
			t.Errorf("Failed to clean up test secret from Keychain: %v", err)
		}
	}()

	// 3. Compile the summon-locksmith binary temporarily for execution
	tmpDir, err := os.MkdirTemp("", "summon-locksmith-e2e")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	binaryPath := filepath.Join(tmpDir, "summon-locksmith")
	cmdCompile := exec.Command("go", "build", "-tags", "locksmith_admin", "-o", binaryPath, ".")
	var compileErr bytes.Buffer
	cmdCompile.Stderr = &compileErr
	if err := cmdCompile.Run(); err != nil {
		t.Fatalf("Failed to compile summon-locksmith binary: %v (stderr: %s)", err, compileErr.String())
	}

	// 4. Run the compiled provider binary directly with the secret ID
	cmdRun := exec.Command(binaryPath, testSecretID)
	var stdout, stderr bytes.Buffer
	cmdRun.Stdout = &stdout
	cmdRun.Stderr = &stderr

	if err := cmdRun.Run(); err != nil {
		t.Fatalf("Failed to execute summon-locksmith binary: %v (stderr: %s)", err, stderr.String())
	}

	// 5. Verify the retrieved secret matches the stored secret exactly
	retrievedVal := stdout.String()
	if retrievedVal != testSecretVal {
		t.Errorf("E2E Validation Failed!\nExpected: %q\nReceived: %q", testSecretVal, retrievedVal)
	} else {
		t.Log("E2E Validation Succeeded! Secret successfully fetched via Keychain after successful biometric authentication.")
	}
}
