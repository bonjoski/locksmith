//go:build manual_test
// +build manual_test

package cmd_test

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// This test suite is designed to be run manually on macOS with Touch ID.
// Run with: go test -v -tags manual_test ./cmd/locksmith/cmd

func TestManualBiometricFlow(t *testing.T) {
	binary := "../../../locksmith"

	t.Run("Add Secret with Biometrics", func(t *testing.T) {
		fmt.Println("\n>>> TEST: Adding secret with biometrics. Please use Touch ID when prompted.")
		cmd := exec.Command(binary, "add", "manual-key", "manual-secret")
		// Simulate 'N' for "module access" to ensure require_biometrics=true
		cmd.Stdin = strings.NewReader("N\n")

		var out, errOut bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &errOut

		err := cmd.Run()
		if err != nil {
			t.Fatalf("Add failed: %v\nOutput: %s\nError: %s", err, out.String(), errOut.String())
		}
		fmt.Println("Add success.")
	})

	t.Run("Get Secret with Biometrics", func(t *testing.T) {
		fmt.Println("\n>>> TEST: Getting secret with biometrics. Please use Touch ID when prompted.")
		cmd := exec.Command(binary, "get", "manual-key")

		var out, errOut bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &errOut

		err := cmd.Run()
		if err != nil {
			t.Fatalf("Get failed: %v\nOutput: %s\nError: %s", err, out.String(), errOut.String())
		}

		if strings.TrimSpace(out.String()) != "manual-secret" {
			t.Errorf("Expected 'manual-secret', got '%s'", out.String())
		}
		fmt.Println("Get success.")
	})

	t.Run("List Secrets", func(t *testing.T) {
		fmt.Println("\n>>> TEST: Listing secrets. This SHOULD NOT prompt for biometrics.")
		cmd := exec.Command(binary, "list")

		var out, errOut bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &errOut

		err := cmd.Run()
		if err != nil {
			t.Fatalf("List failed: %v\nOutput: %s\nError: %s", err, out.String(), errOut.String())
		}

		if !strings.Contains(out.String(), "manual-key") {
			t.Errorf("Expected 'manual-key' in list, got: %s", out.String())
		}
		fmt.Println("List success (no prompt).")
	})

	t.Run("Delete Secret", func(t *testing.T) {
		fmt.Println("\n>>> TEST: Deleting secret. This SHOULD NOT prompt for biometrics (by default).")
		cmd := exec.Command(binary, "delete", "manual-key")

		var out, errOut bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &errOut

		err := cmd.Run()
		if err != nil {
			t.Fatalf("Delete failed: %v\nOutput: %s\nError: %s", err, out.String(), errOut.String())
		}
		fmt.Println("Delete success.")
	})
}
