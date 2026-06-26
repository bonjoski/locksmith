package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/bonjoski/locksmith/v2/pkg/agent"
	"golang.org/x/crypto/ssh"
)

func TestAgentAddCommand(t *testing.T) {
	_, _ = setupTest()

	// Set up temporary home for config/keys
	tmpDir, err := os.MkdirTemp("", "locksmith-cli-agent-test-*")
	if err != nil {
		t.Fatalf("Failed to create tmp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	// 1. Generate an SSH keypair and write private key to file
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}

	sshPrivKey, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	privPath := filepath.Join(tmpDir, "id_ed25519")
	err = os.WriteFile(privPath, pem.EncodeToMemory(sshPrivKey), 0600)
	if err != nil {
		t.Fatalf("Failed to write private key file: %v", err)
	}

	// 2. Mock backend Set since setupTest injects mockBackend which does nothing
	mb := &mockAgentCLIBackend{secrets: make(map[string][]byte)}
	ls.Backend = mb

	// 3. Execute 'locksmith agent add my-key <path>'
	rootCmd.SetArgs([]string{"agent", "add", "my-key", privPath})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("Execute 'agent add' failed: %v", err)
	}

	// 4. Verification
	// Private key stored in vault
	if _, exists := mb.secrets["ssh/my-key"]; !exists {
		t.Error("Private key was not saved in locksmith vault under 'ssh/my-key'")
	}

	// Public key saved in ssh_keys.json
	records, err := agent.LoadSSHKeyRecords()
	if err != nil {
		t.Fatalf("Failed to load SSH key records: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Expected 1 SSH key record, got %d", len(records))
	}
	if records[0].Name != "my-key" {
		t.Errorf("Expected key name 'my-key', got '%s'", records[0].Name)
	}

	sshPubKey, _ := ssh.NewPublicKey(pubKey)
	expectedPubStr := string(ssh.MarshalAuthorizedKey(sshPubKey))
	if records[0].PublicKey != expectedPubStr {
		t.Errorf("Expected public key '%s', got '%s'", expectedPubStr, records[0].PublicKey)
	}
}

type mockAgentCLIBackend struct {
	secrets map[string][]byte
}

func (m *mockAgentCLIBackend) Set(service, account string, data []byte, requireBiometrics bool) error {
	m.secrets[account] = data
	return nil
}

func (m *mockAgentCLIBackend) Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	return m.secrets[account], nil
}

func (m *mockAgentCLIBackend) Delete(service, account string, useBiometrics bool, prompt string) error {
	delete(m.secrets, account)
	return nil
}

func (m *mockAgentCLIBackend) List(service string, useBiometrics bool, prompt string) ([]string, error) {
	return nil, nil
}
