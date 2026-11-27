package redact

import (
	"errors"
	"strings"
	"testing"
)

// TestAdversarial_MutableByteZeroization verifies that TokenMap stores secrets in mutable []byte
// slices that are physically overwritten with zero bytes in place when Zeroize() is called.
func TestAdversarial_MutableByteZeroization(t *testing.T) {
	tm := NewTokenMap()
	rawSecret := "sk-" + "ant-api03-ZeroizeInPlaceVerificationSecret123456"
	ref := tm.Add(rawSecret, "TEST_SECRET")

	tm.mu.RLock()
	internalSlice := tm.refToSecret[ref]
	tm.mu.RUnlock()

	if len(internalSlice) != len(rawSecret) {
		t.Fatalf("expected internal byte slice of len %d, got %d", len(rawSecret), len(internalSlice))
	}

	tm.Zeroize()

	for i, b := range internalSlice {
		if b != 0 {
			t.Fatalf("byte at index %d was not zeroized in place: got 0x%02x", i, b)
		}
	}
	for i, b := range tm.hmacKey {
		if b != 0 {
			t.Fatalf("hmacKey byte at index %d was not zeroized: got 0x%02x", i, b)
		}
	}
}

// TestAdversarial_VaultKeyDescendingPrefixOrder ensures shorter vault secrets never partially
// replace longer vault secrets sharing a common prefix.
func TestAdversarial_VaultKeyDescendingPrefixOrder(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CustomVaultKeys["SHORT_KEY"] = "my_vault_secret"
	cfg.CustomVaultKeys["LONG_KEY"] = "my_vault_secret_extended_prod_suffix"
	engine := NewEngine(cfg)

	for iter := 0; iter < 25; iter++ {
		input := "Connect using my_vault_secret_extended_prod_suffix and fallback my_vault_secret."
		redacted, tm, err := engine.Redact(input)
		if err != nil {
			t.Fatalf("redact failed: %v", err)
		}
		if strings.Contains(redacted, "_extended_prod_suffix") {
			t.Fatalf("prefix leak on iter %d: %s", iter, redacted)
		}
		restored := engine.Restore(redacted, tm)
		if restored != input {
			t.Fatalf("round-trip mismatch on iter %d: got %q, want %q", iter, restored, input)
		}
		tm.Zeroize()
	}
}

// TestAdversarial_ExpandedPatternsUnicodeAndSlidingWindow verifies PKCS#8, gh[pousr]_, github_pat_,
// Bearer, unquoted secrets, Unicode Cf/Tag/Variation Selector stripping, and entropy-dilution defense.
func TestAdversarial_ExpandedPatternsUnicodeAndSlidingWindow(t *testing.T) {
	engine := NewEngine(DefaultConfig())

	pkcs8Body := strings.Join([]string{"MC4CAQ", "AwBQYD", "K2VwBC", "IEIFake", "KeyMat", "erial12", "345678", "90abcdef"}, "")
	ghsTok := strings.Join([]string{"ghs_", "123456", "7890ab", "cdefgh", "ijklmn", "opqrst", "uvwxyz", "ABCD"}, "")
	ghPat := strings.Join([]string{"github_pat_", "11AAAB", "BB0123", "456789_", "abcdef", "ghijkl", "mnopqr", "stuvwxyz", "ABCDEF", "GHIJKL", "MNOPQR", "STUVWXYZ"}, "")
	highEnt := strings.Join([]string{"k9J2m!", "xQ8$vP", "4zL7*w", "R1tY6#", "bN3cV5", "mZ"}, "")
	vectors := []struct {
		name   string
		sample string
		needle string
	}{
		{
			name:   "PKCS8 Private Key",
			sample: "Key:\n-----BEGIN PRIVATE KEY-----\n" + pkcs8Body + "==\n-----END PRIVATE KEY-----",
			needle: pkcs8Body,
		},
		{
			name:   "GitHub Server-to-Server Token ghs_",
			sample: "export GH_TOKEN=" + ghsTok,
			needle: ghsTok,
		},
		{
			name:   "GitHub Fine-Grained PAT",
			sample: "token is " + ghPat,
			needle: "github_pat_" + "11AAAB" + "BB0123" + "456789",
		},
		{
			name:   "Bearer Header Token",
			sample: "Authorization: Bearer superSecretBearerTokenValue_987654321",
			needle: "superSecretBearerTokenValue_987654321",
		},
		{
			name:   "Unquoted Env Secret",
			sample: "DATABASE_PASSWORD=unquotedProdPass_99887766",
			needle: "unquotedProdPass_99887766",
		},
		{
			name:   "Unicode Tag & Variation Selector Smuggling",
			sample: "AKIA\u00ad\ufe0f\U000e0061\U000e0100IOSFODNN7EXAMPLE",
			needle: "IOSFODNN7EXAMPLE",
		},
		{
			name:   "Padding-Diluted High-Entropy Token",
			sample: "padding=" + strings.Repeat("A", 32) + highEnt + strings.Repeat("A", 32),
			needle: highEnt,
		},
	}

	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			redacted, tm, err := engine.Redact(tc.sample)
			if err != nil {
				t.Fatalf("Redact failed: %v", err)
			}
			defer tm.Zeroize()

			if strings.Contains(redacted, tc.needle) {
				t.Errorf("%s leaked in Redact output: %s", tc.name, redacted)
			}
			if err := engine.FailClosedWireGuard([]byte(tc.sample)); !errors.Is(err, ErrSecretLeakageDetected) {
				t.Errorf("%s bypassed FailClosedWireGuard (err=%v)", tc.name, err)
			}
			if err := engine.FailClosedWireGuard([]byte(redacted)); err != nil {
				t.Errorf("FailClosedWireGuard rejected already-redacted payload for %s: %v\nPayload: %s", tc.name, err, redacted)
			}
		})
	}
}

// TestAdversarial_NilTokenMapFailsClosed verifies RedactWithTokenMap refuses a nil TokenMap.
func TestAdversarial_NilTokenMapFailsClosed(t *testing.T) {
	engine := NewEngine(DefaultConfig())
	if _, err := engine.RedactWithTokenMap("AKIA" + "IOSFODNN7EXAMPLE", nil); err == nil {
		t.Fatal("expected RedactWithTokenMap(nil) to fail closed")
	}
}
