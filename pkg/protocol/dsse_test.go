package protocol_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/protocol"
)

func TestETXNewActionConstants(t *testing.T) {
	cases := map[string]protocol.Action{
		"sign_dsse":           protocol.ActionSignDSSE,
		"get_session_pubkey":  protocol.ActionGetSessionPubKey,
		"mint_opaque_lease":   protocol.ActionMintOpaqueLease,
		"redeem_opaque_lease": protocol.ActionRedeemOpaqueLease,
	}
	for want, got := range cases {
		if string(got) != want {
			t.Errorf("expected action %q, got %q", want, got)
		}
	}
}

func TestValidateSessionID(t *testing.T) {
	valid := []string{
		"sess_01JDX9J00ABCDEF",
		"sess_abcd",
		"sess_alpha-01_test",
		"sess_" + strings.Repeat("a", 64),
	}
	for _, id := range valid {
		if err := protocol.ValidateSessionID(id); err != nil {
			t.Errorf("expected valid session_id %q, got error: %v", id, err)
		}
	}

	invalid := []string{
		"",
		"sess_",
		"sess_abc", // too short (<4)
		"sess_" + strings.Repeat("a", 65),
		"other_12345",
		"sess_../etc/passwd",
		"sess_hello world",
		"sess_1234;rm -rf /",
		"sess_1234\n",
	}
	for _, id := range invalid {
		if err := protocol.ValidateSessionID(id); err == nil {
			t.Errorf("expected error for invalid session_id %q, got nil", id)
		}
	}
}

func TestSignDSSERequestValidation(t *testing.T) {
	validPAE := base64.StdEncoding.EncodeToString([]byte("DSSEv1 28 application/vnd.in-toto+json 2 {}"))
	validReq := protocol.SignDSSERequest{
		Version:   protocol.ProtocolVersion,
		Action:    protocol.ActionSignDSSE,
		SessionID: "sess_01JTEST1234",
		PAEB64:    validPAE,
	}
	pae, err := validReq.Validate()
	if err != nil {
		t.Fatalf("expected valid SignDSSERequest, got: %v", err)
	}
	if len(pae) == 0 {
		t.Fatal("expected decoded PAE bytes")
	}

	if got := protocol.SessionKeyID(validReq.SessionID); got != "spiffe://bonjoski.local/session/sess_01JTEST1234" {
		t.Fatalf("unexpected SessionKeyID: %q", got)
	}

	// Empty pae_b64 rejected
	bad := validReq
	bad.PAEB64 = ""
	if _, err := bad.Validate(); err == nil {
		t.Error("expected error for empty pae_b64")
	}

	// Malformed base64 rejected
	bad = validReq
	bad.PAEB64 = "!!!not-base64!!!"
	if _, err := bad.Validate(); err == nil {
		t.Error("expected error for invalid base64 pae_b64")
	}

	// Bad session_id rejected
	bad = validReq
	bad.SessionID = "bad_session"
	if _, err := bad.Validate(); err == nil {
		t.Error("expected error for invalid session_id")
	}

	// Wrong version rejected
	bad = validReq
	bad.Version = "2.0"
	if _, err := bad.Validate(); err == nil {
		t.Error("expected error for unsupported version")
	}
}

func TestOpaqueLeaseRequestValidation(t *testing.T) {
	mint := protocol.MintOpaqueLeaseRequest{
		Version:      protocol.ProtocolVersion,
		Action:       protocol.ActionMintOpaqueLease,
		SessionID:    "sess_01JOPAQUE01",
		SecretName:   "STRIPE_TEST_KEY",
		TargetEnvVar: "STRIPE_API_KEY",
		LeaseTTL:     120 * time.Second,
	}
	if err := mint.Validate(); err != nil {
		t.Fatalf("expected valid MintOpaqueLeaseRequest, got: %v", err)
	}

	// TTL below 1s rejected
	bad := mint
	bad.LeaseTTL = 500 * time.Millisecond
	if err := bad.Validate(); err == nil {
		t.Error("expected error for TTL < 1s")
	}

	// TTL above 300s rejected
	bad = mint
	bad.LeaseTTL = 301 * time.Second
	if err := bad.Validate(); err == nil {
		t.Error("expected error for TTL > 300s")
	}

	// Forbidden env var injection rejected
	bad = mint
	bad.TargetEnvVar = "FOO=BAR\nLD_PRELOAD=/tmp/evil.so"
	if err := bad.Validate(); err == nil {
		t.Error("expected error for env var containing '=' or newline")
	}

	// Default env var falls back to secret_name
	def := mint
	def.TargetEnvVar = ""
	if def.EffectiveEnvVar() != "STRIPE_TEST_KEY" {
		t.Errorf("expected EffectiveEnvVar fallback to secret_name, got %q", def.EffectiveEnvVar())
	}

	// Redeem validation
	redeem := protocol.RedeemOpaqueLeaseRequest{
		Version:   protocol.ProtocolVersion,
		Action:    protocol.ActionRedeemOpaqueLease,
		LeaseID:   "lease_0123456789abcdef0123456789abcdef",
		SessionID: "sess_01JOPAQUE01",
	}
	if err := redeem.Validate(); err != nil {
		t.Fatalf("expected valid RedeemOpaqueLeaseRequest, got: %v", err)
	}

	badRedeem := redeem
	badRedeem.LeaseID = "invalid_handle"
	if err := badRedeem.Validate(); err == nil {
		t.Error("expected error for invalid lease_id")
	}
}
