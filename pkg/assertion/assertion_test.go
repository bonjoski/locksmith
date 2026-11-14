package assertion

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync"
	"testing"
	"time"
)

func TestSignAndVerifyJWTAssertion(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	req := ClientAssertionRequest{
		Audience: "https://idp.example.com/oauth/v2/token",
		Subject:  "developer@company.org",
		Nonce:    "challenge-12345",
		Validity: 30 * time.Second,
		Claims: map[string]any{
			"role": "agent-worker",
		},
	}

	resp, err := SignJWTAssertion(req, priv)
	if err != nil {
		t.Fatalf("SignJWTAssertion failed: %v", err)
	}

	if resp.AssertionType != AssertionTypeJWTBearer {
		t.Errorf("unexpected assertion type: %s", resp.AssertionType)
	}

	// Verify valid token
	claims, err := VerifyJWTAssertion(resp.AssertionToken, &priv.PublicKey, "https://idp.example.com/oauth/v2/token")
	if err != nil {
		t.Fatalf("VerifyJWTAssertion failed: %v", err)
	}

	if claims["sub"] != "developer@company.org" {
		t.Errorf("unexpected sub claim: %v", claims["sub"])
	}
	if claims["jti"] != "challenge-12345" {
		t.Errorf("unexpected jti claim: %v", claims["jti"])
	}
	if claims["role"] != "agent-worker" {
		t.Errorf("unexpected role claim: %v", claims["role"])
	}

	// Test Audience Mismatch
	_, err = VerifyJWTAssertion(resp.AssertionToken, &priv.PublicKey, "https://wrong.audience.com")
	if err == nil {
		t.Error("expected error for audience mismatch, got nil")
	}

	// Test Invalid Signature
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err = VerifyJWTAssertion(resp.AssertionToken, &otherKey.PublicKey, "https://idp.example.com/oauth/v2/token")
	if err == nil {
		t.Error("expected error for signature verification with wrong key, got nil")
	}
}

func TestJWTAssertionExpiration(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Max validity violation
	reqTooLong := ClientAssertionRequest{
		Audience: "https://idp.example.com",
		Subject:  "agent-1",
		Validity: 10 * time.Minute, // Exceeds MaxValidity (5m)
	}
	_, err := SignJWTAssertion(reqTooLong, priv)
	if err == nil {
		t.Error("expected error for validity exceeding MaxValidity, got nil")
	}
}

func TestSynthesizeWebAuthnAssertion(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	req := ClientAssertionRequest{
		Audience: "https://github.com",
		Subject:  "developer",
		Nonce:    "challenge-fido-999",
	}

	resp, err := SynthesizeWebAuthnAssertion(req, priv)
	if err != nil {
		t.Fatalf("SynthesizeWebAuthnAssertion failed: %v", err)
	}

	if resp.AssertionType != AssertionTypeWebAuthn {
		t.Errorf("unexpected assertion type: %s", resp.AssertionType)
	}
	if len(resp.AssertionToken) == 0 {
		t.Error("empty assertion token")
	}
}

func TestSessionAmortizer_MultiAgentConcurrency(t *testing.T) {
	masterSecret := make([]byte, 32)
	_, _ = rand.Read(masterSecret)

	amortizer := NewSessionAmortizer(masterSecret, 15*time.Minute)

	const numSubagents = 8
	var wg sync.WaitGroup
	wg.Add(numSubagents)

	derivedKeys := make([]*ecdsa.PrivateKey, numSubagents)
	errors := make([]error, numSubagents)

	// Simulate N=8 parallel autonomous subagents deriving keys simultaneously
	for i := 0; i < numSubagents; i++ {
		idx := i
		subagentID := "subagent-worktree-" + string(rune('A'+idx))
		go func() {
			defer wg.Done()
			key, err := amortizer.DeriveSubagentKey(subagentID)
			derivedKeys[idx] = key
			errors[idx] = err
		}()
	}

	wg.Wait()

	for i := 0; i < numSubagents; i++ {
		if errors[i] != nil {
			t.Errorf("subagent %d key derivation failed: %v", i, errors[i])
		}
		if derivedKeys[i] == nil {
			t.Errorf("subagent %d key is nil", i)
		}
	}

	// Verify each subagent received a distinct, unique keypair
	for i := 0; i < numSubagents; i++ {
		for j := i + 1; j < numSubagents; j++ {
			if derivedKeys[i].D.Cmp(derivedKeys[j].D) == 0 {
				t.Errorf("subagents %d and %d received identical keys!", i, j)
			}
		}
	}
}
