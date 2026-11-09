//go:build test_native && locksmith_admin

package main

import (
	"math"
	"os/exec"
	"testing"
)

func TestEntropyCheckerLow(t *testing.T) {
	// Low-entropy strings should pass the CI gate (exit status 0).
	cmd := exec.Command("go", "run", "main.go", "4.0", "aaaaaaaaaaaaaaa1", "https://github.com/bonjoski/locksmith")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected zero exit code for low entropy and URL prefix, got %v, output: %s", err, string(output))
	}
}

func TestEntropyCheckerHigh(t *testing.T) {
	// High-entropy strings (>= threshold) must fail the CI gate (exit status 1).
	cmd := exec.Command("go", "run", "main.go", "4.0", "aZ9!bY8@cX7#dW6$")
	output, err := cmd.CombinedOutput()
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() == 0 {
			t.Fatalf("expected non-zero exit code for high entropy, got 0, output: %s", string(output))
		}
	} else {
		t.Fatalf("expected exit error for high entropy string, got %v, output: %s", err, string(output))
	}
}

func TestEntropyCheckerBase64WithSlashDetected(t *testing.T) {
	// Base64 secrets containing '/' and '+' MUST NOT be skipped by path heuristics.
	b64Secret := "wJalrXUtnFEMI" + "/" + "K7MDENG" + "/" + "bPxRfiCYz" + "+98765432"
	cmd := exec.Command("go", "run", "main.go", "4.0", b64Secret)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("LCK-07 regression: Base64 secret containing '/' was skipped! output: %s", string(output))
	}
}

func TestCalculateEntropyUTF8Runes(t *testing.T) {
	// 16 distinct multi-byte UTF-8 runes have exact Shannon entropy log2(16) = 4.0 bits/rune.
	multiByte := "αβγδεζηθικλμνξοπ"
	got := calculateEntropy(multiByte)
	if math.Abs(got-4.0) > 1e-9 {
		t.Fatalf("expected entropy 4.0 for 16 distinct UTF-8 runes, got %f", got)
	}
}
