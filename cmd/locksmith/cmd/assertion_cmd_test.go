package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestSignAssertionCLI(t *testing.T) {
	// 1. Missing audience should error
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"sign-assertion", "--subject", "dev-1"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for missing --audience, got nil")
	}

	// 2. Successful JWT assertion generation
	buf.Reset()
	rootCmd.SetArgs([]string{"sign-assertion", "--audience", "https://idp.local/token", "--subject", "dev-1", "--nonce", "test-nonce-1"})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("sign-assertion failed: %v", err)
	}

	out := strings.TrimSpace(buf.String())
	parts := strings.Split(out, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d: %s", len(parts), out)
	}

	// 3. Successful WebAuthn assertion generation
	buf.Reset()
	rootCmd.SetArgs([]string{"sign-assertion", "--audience", "https://github.com", "--subject", "dev-1", "--format", "webauthn"})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("sign-assertion webauthn failed: %v", err)
	}
	if !strings.Contains(buf.String(), "client_data_json") {
		t.Errorf("expected client_data_json in webauthn output: %s", buf.String())
	}
}
