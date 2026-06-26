package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"golang.org/x/crypto/ssh"
)

func generateTestKeypair(t *testing.T) (ssh.PublicKey, []byte, string) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}

	sshPrivKey, err := ssh.MarshalPrivateKey(privKey, "test comment")
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	pubKeyStr := string(ssh.MarshalAuthorizedKey(sshPubKey))

	return sshPubKey, pem.EncodeToMemory(sshPrivKey), pubKeyStr
}

func setupAgentTestEnv(t *testing.T, privateKeyBytes []byte, pubKeyStr string) (*LocksmithAgent, func()) {
	tmpDir, err := os.MkdirTemp("", "locksmith-agent-test-*")
	if err != nil {
		t.Fatalf("Failed to create tmp dir: %v", err)
	}

	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)

	record := SSHKeyRecord{
		Name:      "test-key",
		PublicKey: pubKeyStr,
	}
	if err := SaveSSHKeyRecords([]SSHKeyRecord{record}); err != nil {
		t.Fatalf("SaveSSHKeyRecords failed: %v", err)
	}

	mc := &mockAgentCache{secrets: make(map[string]locksmith.Secret)}
	mb := &mockAgentBackend{secrets: make(map[string][]byte)}

	secret := locksmith.Secret{
		Value:     privateKeyBytes,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	secretData, _ := json.Marshal(secret)
	mb.secrets["ssh/test-key"] = secretData

	ls := locksmith.NewWithCache(mc)
	ls.Backend = mb

	cleanup := func() {
		os.Setenv("HOME", origHome)
		os.RemoveAll(tmpDir)
	}

	return NewLocksmithAgent(ls), cleanup
}

func TestAgentListAndSign(t *testing.T) {
	sshPubKey, privKeyBytes, pubKeyStr := generateTestKeypair(t)
	agentInst, cleanup := setupAgentTestEnv(t, privKeyBytes, pubKeyStr)
	defer cleanup()

	// Test List
	keys, err := agentInst.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("Expected 1 key, got %d", len(keys))
	}
	if keys[0].Comment != "test-key" {
		t.Errorf("Expected comment 'test-key', got '%s'", keys[0].Comment)
	}

	// Verify key blobs match
	parsedPubKey, err := ssh.ParsePublicKey(keys[0].Blob)
	if err != nil {
		t.Fatalf("Failed to parse public key blob: %v", err)
	}
	if !bytes.Equal(parsedPubKey.Marshal(), sshPubKey.Marshal()) {
		t.Error("Public key blobs do not match")
	}

	// Test Sign
	testData := []byte("hello world")
	sig, err := agentInst.Sign(parsedPubKey, testData)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify signature
	err = parsedPubKey.Verify(testData, sig)
	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}

	// Test lazySigners
	signers, err := agentInst.Signers()
	if err != nil {
		t.Fatalf("Signers failed: %v", err)
	}
	lazySig, err := signers[0].Sign(rand.Reader, testData)
	if err != nil {
		t.Fatalf("Lazy signer Sign failed: %v", err)
	}
	err = parsedPubKey.Verify(testData, lazySig)
	if err != nil {
		t.Errorf("Lazy signer signature verification failed: %v", err)
	}
}

func TestRunPinentry(t *testing.T) {
	mc := &mockAgentCache{secrets: make(map[string]locksmith.Secret)}
	mb := &mockAgentBackend{secrets: make(map[string][]byte)}

	secret := locksmith.Secret{
		Value:     []byte("super-gpg-passphrase"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	secretData, _ := json.Marshal(secret)
	mb.secrets["gpg/passphrase"] = secretData

	ls := locksmith.NewWithCache(mc)
	ls.Backend = mb

	inputReader, inputWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe failed: %v", err)
	}
	defer inputReader.Close()
	defer inputWriter.Close()

	outputReader, outputWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe failed: %v", err)
	}
	defer outputReader.Close()
	defer outputWriter.Close()

	oldStdin := os.Stdin
	oldStdout := os.Stdout
	os.Stdin = inputReader
	os.Stdout = outputWriter
	defer func() {
		os.Stdin = oldStdin
		os.Stdout = oldStdout
	}()

	errChan := make(chan error, 1)
	go func() {
		errChan <- RunPinentry(ls)
	}()

	buf := make([]byte, 1024)
	n, _ := outputReader.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "OK") {
		t.Errorf("Expected initial OK, got: %s", string(buf[:n]))
	}

	_, _ = inputWriter.Write([]byte("GETPIN\nBYE\n"))

	n, _ = outputReader.Read(buf)
	resp := string(buf[:n])

	if !strings.Contains(resp, "D super-gpg-passphrase") {
		t.Errorf("Expected GPG passphrase in output, got: %s", resp)
	}

	_ = outputWriter.Close()

	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("RunPinentry returned error: %v", err)
		}
	case <-time.After(time.Second * 2):
		t.Error("RunPinentry timed out")
	}
}

type mockAgentCache struct {
	secrets map[string]locksmith.Secret
}

func (m *mockAgentCache) Set(key string, secret locksmith.Secret, ttl time.Duration) error {
	m.secrets[key] = secret
	return nil
}

func (m *mockAgentCache) Get(key string) (*locksmith.Secret, error) {
	s, ok := m.secrets[key]
	if !ok {
		return nil, nil
	}
	return &s, nil
}

func (m *mockAgentCache) Delete(key string) error {
	delete(m.secrets, key)
	return nil
}

func (m *mockAgentCache) IsExpired(key string, ttl time.Duration) bool {
	return false
}

type mockAgentBackend struct {
	secrets map[string][]byte
}

func (m *mockAgentBackend) Set(service, account string, data []byte, requireBiometrics bool) error {
	m.secrets[account] = data
	return nil
}

func (m *mockAgentBackend) Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	return m.secrets[account], nil
}

func (m *mockAgentBackend) Delete(service, account string, useBiometrics bool, prompt string) error {
	delete(m.secrets, account)
	return nil
}

func (m *mockAgentBackend) List(service string, useBiometrics bool, prompt string) ([]string, error) {
	keys := make([]string, 0, len(m.secrets))
	for k := range m.secrets {
		keys = append(keys, k)
	}
	return keys, nil
}
