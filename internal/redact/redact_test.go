package redact

import (
	"strings"
	"testing"
)

func TestEntropyCalculation(t *testing.T) {
	low := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if ShannonEntropy(low) != 0.0 {
		t.Fatalf("expected 0 entropy for uniform string, got %f", ShannonEntropy(low))
	}

	english := "This is a normal sentence with typical english words and frequent letters."
	entEng := ShannonEntropy(english)
	if entEng < 2.0 || entEng > 4.2 {
		t.Fatalf("expected english text entropy around 3.5, got %f", entEng)
	}

	high := "k9J2m!xQ8$vP4zL7*wR1tY6#bN3cV5mZ"
	entHigh := ShannonEntropy(high)
	if entHigh < 4.5 {
		t.Fatalf("expected high entropy for base64 key, got %f", entHigh)
	}
}

func TestRedactionAndRestore(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CustomVaultKeys["MY_DB_PASS"] = "SuperSecretPassword999!"
	engine := NewEngine(cfg)

	awsSecret := "AKIA" + "IOSFODNN7EXAMPLE"
	anthropicSecret := strings.Join([]string{"sk-", "ant-api03-", "abcdef", "ghijkl", "mnopqr", "stuvwxyz", "123456", "7890_test"}, "")
	rawInput := `
// Database configuration
const dbUrl = "postgres://admin:SuperSecretPassword999!@db.prod.internal:5432/main";
const awsKey = "` + awsSecret + `";
const anthropicKey = "` + anthropicSecret + `";
const normalText = "Please refactor this code to use connection pooling.";
`

	redacted, tm, err := engine.Redact(rawInput)
	if err != nil {
		t.Fatalf("redact failed: %v", err)
	}
	defer tm.Zeroize()

	if strings.Contains(redacted, "SuperSecretPassword999!") {
		t.Errorf("vault secret was not redacted")
	}
	if strings.Contains(redacted, "AKIA" + "IOSFODNN7EXAMPLE") {
		t.Errorf("AWS key was not redacted")
	}
	if strings.Contains(redacted, "sk-" + "ant-api03") {
		t.Errorf("Anthropic key was not redacted")
	}
	if !strings.Contains(redacted, "[SECRET_REF_") {
		t.Errorf("expected placeholder token in redacted text, got:\n%s", redacted)
	}

	unredactedBytes := []byte("Here is my key: AKIA" + "IOSFODNN7EXAMPLE")
	if err := engine.FailClosedWireGuard(unredactedBytes); err == nil {
		t.Errorf("expected FailClosedWireGuard to block unredacted AWS key")
	}
	if err := engine.FailClosedWireGuard([]byte(redacted)); err != nil {
		t.Errorf("expected FailClosedWireGuard to pass on redacted payload, got: %v", err)
	}

	restored := engine.Restore(redacted, tm)
	if !strings.Contains(restored, "SuperSecretPassword999!") {
		t.Errorf("restored text does not contain original vault secret")
	}
	if !strings.Contains(restored, "AKIA" + "IOSFODNN7EXAMPLE") {
		t.Errorf("restored text does not contain original AWS key")
	}
}

func TestTokenMapZeroization(t *testing.T) {
	tm := NewTokenMap()
	ref := tm.Add("Secret123456", "test")
	if count := tm.Count(); count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}

	tm.Zeroize()
	if count := tm.Count(); count != 0 {
		t.Fatalf("expected count 0 after zeroize, got %d", count)
	}
	if _, ok := tm.GetSecret(ref); ok {
		t.Fatalf("expected secret to be purged from map")
	}
}
