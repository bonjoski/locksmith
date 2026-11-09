package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

type errorMockAgentBackend struct {
	err error
}

func (m *errorMockAgentBackend) Set(service, account string, data []byte, requireBiometrics bool) error {
	return m.err
}

func (m *errorMockAgentBackend) Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	return nil, m.err
}

func (m *errorMockAgentBackend) Delete(service, account string, useBiometrics bool, prompt string) error {
	return m.err
}

func (m *errorMockAgentBackend) List(service string, useBiometrics bool, prompt string) ([]string, error) {
	return nil, m.err
}

// TestAdversarial_LCK09_AssuanPercentEncodingBlocksCommandInjection verifies that
// Assuan SETDESC, SETPROMPT, D (data), and ERR lines percent-encode '%', '\r', '\n',
// and '\x00' so untrusted prompts/passphrases/errors cannot inject Assuan commands.
func TestAdversarial_LCK09_AssuanPercentEncodingBlocksCommandInjection(t *testing.T) {
	payload := "Key 100%\r\nGETPIN\nD injected\x00tail"

	encoded := AssuanPercentEncode(payload)
	if strings.ContainsAny(encoded, "\r\n\x00") {
		t.Fatalf("CRITICAL (LCK-09): AssuanPercentEncode left raw control characters: %q", encoded)
	}
	const want = "Key 100%25%0D%0AGETPIN%0AD injected%00tail"
	if encoded != want {
		t.Fatalf("AssuanPercentEncode mismatch: got %q, want %q", encoded, want)
	}

	descLine := FormatAssuanSetDesc("Unlock %s\r\nBYE")
	if descLine != "SETDESC Unlock %25s%0D%0ABYE" {
		t.Fatalf("unexpected FormatAssuanSetDesc output: %q", descLine)
	}

	promptLine := FormatAssuanSetPrompt("PIN:\r\nD pwned")
	if promptLine != "SETPROMPT PIN:%0D%0AD pwned" {
		t.Fatalf("unexpected FormatAssuanSetPrompt output: %q", promptLine)
	}

	// End-to-end RunPinentryWithIO check with multiline/percent passphrase and RequireBiometrics preservation.
	t.Setenv("LOCKSMITH_AUDIT_PATH", t.TempDir()+"/audit.jsonl")

	mc := &mockAgentCache{secrets: make(map[string]locksmith.Secret)}
	mb := &mockAgentBackend{secrets: make(map[string][]byte)}
	secBytes, err := json.Marshal(locksmith.Secret{
		Value:     []byte("pass%phrase\r\nOK\nERR 1 injected"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("marshal secret: %v", err)
	}
	mb.secrets["gpg/passphrase"] = secBytes

	ls := &locksmith.Locksmith{
		Service: "test-pinentry",
		Backend: mb,
		Cache:   mc,
		Options: locksmith.Options{RequireBiometrics: true},
	}

	var out bytes.Buffer
	if err := RunPinentryWithIO(strings.NewReader("SETDESC Key\r\nSETPROMPT PIN:\nGETPIN\nBYE\n"), &out, ls); err != nil {
		t.Fatalf("RunPinentryWithIO failed: %v", err)
	}

	if !ls.Options.RequireBiometrics {
		t.Fatal("CRITICAL: RunPinentryWithIO mutated ls.Options.RequireBiometrics")
	}

	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	for _, line := range lines {
		if strings.ContainsAny(line, "\r\x00") {
			t.Fatalf("CRITICAL (LCK-09): raw CR/NUL emitted in Assuan stream: %q", line)
		}
		if line == "ERR 1 injected" {
			t.Fatalf("CRITICAL (LCK-09): unescaped newline in passphrase injected Assuan frame: %q", out.String())
		}
	}
	if !strings.Contains(out.String(), "D pass%25phrase%0D%0AOK%0AERR 1 injected\n") {
		t.Fatalf("expected percent-encoded Assuan D frame, got: %q", out.String())
	}

	// Error frame injection check when backend returns multiline error message.
	lsErr := &locksmith.Locksmith{
		Service: "test-pinentry-err",
		Backend: &errorMockAgentBackend{err: errors.New("vault locked\r\nD forged-pin\nOK")},
		Cache:   &mockAgentCache{secrets: make(map[string]locksmith.Secret)},
	}
	var errOut bytes.Buffer
	if err := RunPinentryWithIO(strings.NewReader("GETPIN\nBYE\n"), &errOut, lsErr); err != nil {
		t.Fatalf("RunPinentryWithIO error session failed: %v", err)
	}
	if strings.Contains(errOut.String(), "\nD forged-pin") {
		t.Fatalf("CRITICAL (LCK-09): backend error injected forged Assuan D line: %q", errOut.String())
	}
}
