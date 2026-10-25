package cmd

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/stepup"
)

func TestStepUpCommand_Basic(t *testing.T) {
	outBuf, errBuf := setupTest()

	// Mock the biometric authenticator to succeed
	seenPrompt := ""
	stepUpAuthenticator = func(prompt string) error {
		seenPrompt = prompt
		return nil
	}
	defer func() {
		stepUpAuthenticator = nil
		stepUpChallenge = ""
		stepUpSeverity = "CRITICAL"
		stepUpTTL = 5 * time.Minute
		stepUpRaw = false
		stepUpVerify = ""
	}()

	rootCmd.SetArgs([]string{"step-up", "--challenge=Approve raw disk write", "--severity=CRITICAL"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("step-up command failed: %v (stderr: %s)", err, errBuf.String())
	}

	if seenPrompt != "[Locksmith CRITICAL] Approve raw disk write" {
		t.Errorf("expected prompt '[Locksmith CRITICAL] Approve raw disk write', got: %q", seenPrompt)
	}

	outStr := outBuf.String()
	var token stepup.AttestationToken
	if err := json.Unmarshal([]byte(outStr), &token); err != nil {
		t.Fatalf("failed to parse attestation token JSON output: %v (output: %s)", err, outStr)
	}

	if token.Claims.Challenge != "Approve raw disk write" {
		t.Errorf("expected challenge 'Approve raw disk write', got %q", token.Claims.Challenge)
	}
	if token.Claims.Severity != stepup.SeverityCritical {
		t.Errorf("expected severity CRITICAL, got %q", token.Claims.Severity)
	}
	if token.RawToken == "" {
		t.Errorf("expected non-empty RawToken")
	}

	// Now test verification via CLI
	outBuf.Reset()
	errBuf.Reset()
	rootCmd.SetArgs([]string{"step-up", "--verify=" + token.RawToken, "--raw"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("verification command failed: %v", err)
	}
	if !strings.Contains(outBuf.String(), "VALID") {
		t.Errorf("expected 'VALID', got: %s", outBuf.String())
	}
}

func TestStepUpCommand_RawOutput(t *testing.T) {
	outBuf, _ := setupTest()

	stepUpAuthenticator = func(prompt string) error { return nil }
	defer func() {
		stepUpAuthenticator = nil
		stepUpChallenge = ""
		stepUpRaw = false
	}()

	rootCmd.SetArgs([]string{"step-up", "--challenge=Format NVMe", "--severity=HIGH", "--raw"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	rawToken := strings.TrimSpace(outBuf.String())
	parts := strings.Split(rawToken, ".")
	if len(parts) != 2 {
		t.Fatalf("expected raw token in format <payload>.<sig>, got: %s", rawToken)
	}
}

func TestStepUpCommand_Refusal(t *testing.T) {
	_, errBuf := setupTest()

	stepUpAuthenticator = func(prompt string) error {
		return errors.New("User canceled authentication")
	}
	defer func() {
		stepUpAuthenticator = nil
		stepUpChallenge = ""
	}()

	rootCmd.SetArgs([]string{"step-up", "--challenge=Delete Database", "--severity=CRITICAL"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatalf("expected error on user cancellation, got nil")
	}
	if !strings.Contains(err.Error(), "canceled") && !strings.Contains(errBuf.String(), "canceled") {
		t.Errorf("expected cancellation in error message, got: %v", err)
	}
}
