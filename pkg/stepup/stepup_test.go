package stepup_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/stepup"
)

func TestStepUp_AuthorizeAndVerify(t *testing.T) {
	ctx := context.Background()

	// 1. Generate test keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 test key: %v", err)
	}

	authPromptSeen := ""
	mockAuth := func(prompt string) error {
		authPromptSeen = prompt
		return nil
	}

	req := stepup.StepUpRequest{
		Challenge: "Approve raw disk write",
		Severity:  stepup.SeverityCritical,
		TTL:       5 * time.Minute,
		Audience:  "aegisbox",
	}

	token, err := stepup.Authorize(ctx, req,
		stepup.WithAuthenticator(mockAuth),
		stepup.WithPrivateKey(priv),
	)
	if err != nil {
		t.Fatalf("stepup.Authorize failed: %v", err)
	}

	if authPromptSeen != "[Locksmith CRITICAL] Approve raw disk write" {
		t.Errorf("unexpected prompt: got %q", authPromptSeen)
	}

	if token.Claims.Challenge != "Approve raw disk write" {
		t.Errorf("unexpected challenge in claims: %q", token.Claims.Challenge)
	}
	if token.Claims.Severity != stepup.SeverityCritical {
		t.Errorf("unexpected severity: %q", token.Claims.Severity)
	}
	if token.RawToken == "" {
		t.Errorf("raw token string cannot be empty")
	}

	// 2. Verify attestation token with public key
	verified, err := stepup.Verify(token.RawToken, pub)
	if err != nil {
		t.Fatalf("stepup.Verify failed: %v", err)
	}
	if verified.Claims.TokenID != token.Claims.TokenID {
		t.Errorf("token ID mismatch: %s != %s", verified.Claims.TokenID, token.Claims.TokenID)
	}

	// 3. Test verification failure with wrong public key
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := stepup.Verify(token.RawToken, wrongPub); err == nil {
		t.Errorf("expected signature verification to fail with wrong public key, got nil")
	}

	// 4. Test biometric refusal / cancellation
	refusalAuth := func(prompt string) error {
		return errors.New("User canceled authentication")
	}
	if _, err := stepup.Authorize(ctx, req, stepup.WithAuthenticator(refusalAuth), stepup.WithPrivateKey(priv)); err == nil {
		t.Errorf("expected error on biometric rejection, got nil")
	}
}

func TestStepUp_Expiration(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	mockAuth := func(prompt string) error {
		return nil
	}

	req := stepup.StepUpRequest{
		Challenge: "Format NVMe Block Device",
		Severity:  stepup.SeverityHigh,
		TTL:       10 * time.Millisecond,
	}

	token, err := stepup.Authorize(context.Background(), req,
		stepup.WithAuthenticator(mockAuth),
		stepup.WithPrivateKey(priv),
	)
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}

	// Wait for expiration
	time.Sleep(1500 * time.Millisecond)

	if _, err := stepup.Verify(token.RawToken, pub); err == nil {
		t.Errorf("expected token to be expired, but verification succeeded")
	}
}

func TestStepUp_TamperedPayload(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mockAuth := func(prompt string) error { return nil }

	req := stepup.StepUpRequest{
		Challenge: "Mount loop device",
		Severity:  stepup.SeverityMedium,
	}

	token, err := stepup.Authorize(context.Background(), req,
		stepup.WithAuthenticator(mockAuth),
		stepup.WithPrivateKey(priv),
	)
	if err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}

	// Tamper with payload
	tamperedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"challenge":"HACKED"}`))
	tamperedToken := tamperedPayload + "." + token.Signature

	if _, err := stepup.Verify(tamperedToken, pub); err == nil {
		t.Errorf("expected tampered token to fail verification")
	}
}
