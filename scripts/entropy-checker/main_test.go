//go:build test_native && locksmith_admin

package main

import (
	"os/exec"
	"testing"
)

func TestEntropyCheckerLow(t *testing.T) {
	// Provide a low‑entropy string; expect the program to exit with a non‑zero status.
	cmd := exec.Command("go", "run", "main.go", "4.0", "aaaaaaaaaaaaaaa1")
	output, err := cmd.CombinedOutput()
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() == 0 {
			t.Fatalf("expected non‑zero exit code for low entropy, got 0, output: %s", string(output))
		}
	} else {
		t.Fatalf("expected exit error, got %v, output: %s", err, string(output))
	}
}

func TestEntropyCheckerHigh(t *testing.T) {
	// Provide a higher‑entropy string; program should exit with status 0.
	cmd := exec.Command("go", "run", "main.go", "4.0", "aZ9!bY8@cX7#dW6$")
	if err := cmd.Run(); err != nil {
		t.Fatalf("expected zero exit code for high entropy, got error: %v", err)
	}
}
