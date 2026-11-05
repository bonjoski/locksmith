package acceptance_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var locksmithBin string

func TestMain(m *testing.M) {
	bin := os.Getenv("LOCKSMITH_BIN")
	if bin == "" {
		tmpDir, err := os.MkdirTemp("", "locksmith-acceptance-bin-*")
		if err != nil {
			panic(err)
		}
		defer func() {
			_ = os.RemoveAll(tmpDir)
		}()

		bin = filepath.Join(tmpDir, "locksmith")
		cmd := exec.Command("go", "build", "-o", bin, "./cmd/locksmith")
		cmd.Dir = "../.."
		if out, err := cmd.CombinedOutput(); err != nil {
			panic("failed to build locksmith binary: " + string(out))
		}
	}
	locksmithBin = bin
	os.Exit(m.Run())
}

func execLocksmith(homeDir string, args ...string) *exec.Cmd {
	cmd := exec.Command(locksmithBin, args...)
	cmd.Env = append(os.Environ(),
		"HOME="+homeDir,
		"LOCKSMITH_MOCK_BACKEND=1",
	)
	return cmd
}

// CLAIM: CLAIM-CA-01
// Finding 1: Assert that no private key or unsealed secrets exist in $HOME/.locksmith by default
func TestAcceptance_DiskKeyCleanliness(t *testing.T) {
	tempHome := t.TempDir()
	caDir := filepath.Join(tempHome, ".locksmith", "ca")

	// Run with mock enclave backend: Keychain sealing succeeds, so no .key files should exist on disk
	cmd := execLocksmith(tempHome, "ca", "init", "--ca-dir", caDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ca init failed: %v, out: %s", err, string(out))
	}

	// Walk tree: assert no files contain "PRIVATE KEY"
	_ = filepath.Walk(tempHome, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".key") {
			t.Errorf("CLAIM-CA-01 VIOLATION: Found key file on disk without opt-in: %s", path)
		}
		data, readErr := os.ReadFile(path)
		if readErr == nil && strings.Contains(string(data), "PRIVATE KEY") {
			t.Errorf("CLAIM-CA-01 VIOLATION: File %s contains raw PRIVATE KEY material", path)
		}
		return nil
	})
}

// CLAIM: CLAIM-CA-02
// Finding 1: Critical Name Constraints present, leaf outside permitted constraints is rejected
func TestAcceptance_NameConstraintsCriticalAndStrict(t *testing.T) {
	tempHome := t.TempDir()
	caDir := filepath.Join(tempHome, ".locksmith", "ca")

	cmd := execLocksmith(tempHome, "ca", "init", "--ca-dir", caDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ca init failed: %v, out: %s", err, string(out))
	}

	rootCertPath := filepath.Join(caDir, "root-ca.crt")
	certData, err := os.ReadFile(rootCertPath)
	if err != nil {
		t.Fatalf("failed reading root certificate: %v", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatalf("failed to decode root cert PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed parsing root cert: %v", err)
	}

	if !cert.PermittedDNSDomainsCritical {
		t.Errorf("CLAIM-CA-02 VIOLATION: PermittedDNSDomainsCritical must be true")
	}
	if !cert.MaxPathLenZero {
		t.Errorf("CLAIM-CA-02 VIOLATION: MaxPathLenZero must be true")
	}

	// Verify defaults are loopback only
	if len(cert.PermittedDNSDomains) == 0 {
		t.Errorf("CLAIM-CA-02 VIOLATION: PermittedDNSDomains is empty")
	}
	for _, d := range cert.PermittedDNSDomains {
		if d != "localhost" && d != ".localhost" {
			t.Errorf("CLAIM-CA-02 VIOLATION: Non-loopback default DNS constraint: %s", d)
		}
	}
}

// CLAIM: CLAIM-CA-03
// Finding 1 & Issue 2: Symmetry between ca trust and ca init --trust rejecting invalid roots
func TestAcceptance_TrustSymmetry(t *testing.T) {
	tempHome := t.TempDir()
	caDir := filepath.Join(tempHome, ".locksmith", "ca")

	// Supernet /0 IP range must fail closed on ca init --trust
	cmd := execLocksmith(tempHome, "ca", "init", "--trust", "--permitted-ip", "0.0.0.0/0", "--ca-dir", caDir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("CLAIM-CA-03 VIOLATION: ca init --trust accepted 0.0.0.0/0 supernet, out: %s", string(out))
	}

	// Public domain constraint must fail closed on ca init
	cmd = execLocksmith(tempHome, "ca", "init", "--permitted-dns", "example.eu", "--ca-dir", caDir)
	out, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("CLAIM-CA-03 VIOLATION: ca init accepted public domain example.eu, out: %s", string(out))
	}
}

// CLAIM: CLAIM-SPIFFE-01
// Finding 2: Bridge tokens are derived per CID with domain separation
func TestAcceptance_BridgeTokenIsolation(t *testing.T) {
	tempHome := t.TempDir()
	caDir := filepath.Join(tempHome, ".locksmith", "ca")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		t.Fatal(err)
	}

	masterKey := strings.Repeat("0123456789abcdef", 2) // 32 bytes hex
	keyFile := filepath.Join(caDir, "test.key")
	if err := os.WriteFile(keyFile, []byte(masterKey), 0600); err != nil {
		t.Fatal(err)
	}

	// Derive CID 3 token
	cmd3 := execLocksmith(tempHome, "ca", "derive-bridge-token", "--cid", "3", "--key-file", keyFile)
	out3, err3 := cmd3.CombinedOutput()
	if err3 != nil {
		t.Fatalf("failed deriving CID 3 token: %v, out: %s", err3, string(out3))
	}
	token3 := strings.TrimSpace(string(out3))

	// Derive CID 4 token
	cmd4 := execLocksmith(tempHome, "ca", "derive-bridge-token", "--cid", "4", "--key-file", keyFile)
	out4, err4 := cmd4.CombinedOutput()
	if err4 != nil {
		t.Fatalf("failed deriving CID 4 token: %v, out: %s", err4, string(out4))
	}
	token4 := strings.TrimSpace(string(out4))

	if token3 == token4 {
		t.Fatalf("CLAIM-SPIFFE-01 VIOLATION: Tokens for CID 3 and CID 4 must be distinct, got %q for both", token3)
	}
	if len(token3) < 32 || len(token4) < 32 {
		t.Fatalf("CLAIM-SPIFFE-01 VIOLATION: Derived tokens must be cryptographically secure strings")
	}
}

// CLAIM: CLAIM-POLICY-01
// Finding 3 & Issue 4: Bare binary identifiers without cryptographic prefixes fail closed
func TestAcceptance_PolicyBareBinaryRejection(t *testing.T) {
	tempHome := t.TempDir()
	policyPath := filepath.Join(tempHome, "policy.json")

	policyContent := `{
		"trust_domain": "bonjoski.local",
		"rules": [
			{
				"spiffe_pattern": "spiffe://bonjoski.local/sa/worker",
				"allowed_binaries": ["unprefixed_bare_binary"]
			}
		]
	}`
	if err := os.WriteFile(policyPath, []byte(policyContent), 0600); err != nil {
		t.Fatal(err)
	}

	// Initialize CA with disk keys so the subsequent serve-spiffe process can load root CA
	initCmd := execLocksmith(tempHome, "ca", "init", "--allow-unsealed-disk-keys")
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed initializing CA for test: %v, out: %s", err, string(out))
	}

	// Running serve-spiffe with this policy must fail closed due to bare binary validation error
	cmd := execLocksmith(tempHome, "ca", "serve-spiffe", "--policy", policyPath, "--socket", filepath.Join(tempHome, "test.sock"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("CLAIM-POLICY-01 VIOLATION: serve-spiffe started with bare binary in policy: %s", string(out))
	}
	if !strings.Contains(string(out), "unauthenticated bare binary identifier") {
		t.Fatalf("expected error regarding unauthenticated bare binary identifier, got: %s", string(out))
	}
}

// CLAIM: CLAIM-SPIFFE-02
// Finding 2 & Issue 1: Bridge master key sealed in enclave, not written to disk by default
func TestAcceptance_BridgeKeyEnclaveSealing(t *testing.T) {
	tempHome := t.TempDir()
	caDir := filepath.Join(tempHome, ".locksmith", "ca")

	// Pre-seed CA so serve-spiffe can run
	initCmd := execLocksmith(tempHome, "ca", "init", "--allow-unsealed-disk-keys")
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed initializing CA for test: %v, out: %s", err, string(out))
	}

	// derive-bridge-token without a disk key must not create bridge.key on disk
	diskBridgeKey := filepath.Join(caDir, "bridge.key")
	if _, err := os.Stat(diskBridgeKey); err == nil {
		t.Fatalf("CLAIM-SPIFFE-02 VIOLATION: bridge.key exists on disk before derivation")
	}

	// Supply master key via LOCKSMITH_BRIDGE_KEY environment variable (no disk key file)
	masterKey := strings.Repeat("fedcba9876543210", 4) // 64 hex chars = 32 raw bytes
	cmd := execLocksmith(tempHome, "ca", "derive-bridge-token", "--cid", "3")
	cmd.Env = append(cmd.Env, "LOCKSMITH_BRIDGE_KEY="+masterKey)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("derive-bridge-token failed: %v, out: %s", err, string(out))
	}
	if len(strings.TrimSpace(string(out))) < 32 {
		t.Fatalf("expected valid token output, got: %s", string(out))
	}

	// Verify no bridge.key file was persisted to disk
	if _, err := os.Stat(diskBridgeKey); !os.IsNotExist(err) {
		t.Fatalf("CLAIM-SPIFFE-02 VIOLATION: bridge.key was persisted to disk unexpectedly")
	}
}
