package locksmith

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func setupSliceTestLocksmith(t *testing.T, secrets map[string]string) *Locksmith {
	t.Helper()
	mc := &MockCache{secrets: make(map[string]Secret)}
	backendSecrets := make(map[string][]byte)

	for k, v := range secrets {
		sec := Secret{
			Value:     []byte(v),
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		data, _ := json.Marshal(sec)
		backendSecrets[k] = data
	}

	mb := &testBackend{secrets: backendSecrets}
	ls := NewWithCache(mc)
	ls.Backend = mb
	return ls
}

func TestRunSliceExplicitKey(t *testing.T) {
	ls := setupSliceTestLocksmith(t, map[string]string{
		"production/db_password": "SuperSecretPasswordValue",
	})

	code, err := ls.RunSlice([]string{"true"}, "production/db_password", "")
	if err != nil {
		t.Fatalf("RunSlice failed: %v", err)
	}
	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}
}

func TestRunSlicePythonChild(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available in PATH, skipping python child test")
	}

	secretKey := "api/stripe_key"
	secretVal := "sk_live_1234567890abcdef_special_token"

	ls := setupSliceTestLocksmith(t, map[string]string{
		secretKey: secretVal,
	})

	pyScript := `
import os, sys

fd_str = os.environ.get('LOCKSMITH_FD', '')
if fd_str != '3':
    sys.stderr.write(f"Invalid LOCKSMITH_FD: {fd_str}\n")
    sys.exit(2)

fd = int(fd_str)

# 1. Verify /proc/self/environ or os.environ has zero secret plaintext
env_dump = str(os.environ)
if 'sk_live_1234567890abcdef_special_token' in env_dump:
    sys.stderr.write("LEAK DETECTED: Secret found in process environment table!\n")
    sys.exit(3)

# 2. Read from inherited file descriptor 3
with os.fdopen(fd) as f:
    content = f.read()
    if content != 'sk_live_1234567890abcdef_special_token':
        sys.stderr.write(f"Content mismatch: got {content}\n")
        sys.exit(4)

sys.exit(0)
`

	code, err := ls.RunSlice([]string{"python3", "-c", pyScript}, secretKey, "")
	if err != nil {
		t.Fatalf("RunSlice execution error: %v", err)
	}
	if code != 0 {
		t.Fatalf("Python child exited with error code: %d", code)
	}
}

func TestRunSliceNodeChild(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available in PATH, skipping node child test")
	}

	secretKey := "aws/secret_access_key"
	secretVal := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	ls := setupSliceTestLocksmith(t, map[string]string{
		secretKey: secretVal,
	})

	nodeScript := `
const fs = require('fs');

const fdStr = process.env.LOCKSMITH_FD;
if (fdStr !== '3') {
    process.stderr.write('Invalid LOCKSMITH_FD: ' + fdStr + '\n');
    process.exit(2);
}

// 1. Verify process.env does NOT contain the secret string
const envStr = JSON.stringify(process.env);
if (envStr.includes('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')) {
    process.stderr.write('LEAK DETECTED: Secret found in process.env!\n');
    process.exit(3);
}

// 2. Read secret from inherited file descriptor 3
const secret = fs.readFileSync(3, 'utf8');
if (secret !== 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY') {
    process.stderr.write('Content mismatch: ' + secret + '\n');
    process.exit(4);
}

process.exit(0);
`

	code, err := ls.RunSlice([]string{"node", "-e", nodeScript}, secretKey, "")
	if err != nil {
		t.Fatalf("RunSlice execution error: %v", err)
	}
	if code != 0 {
		t.Fatalf("Node child exited with error code: %d", code)
	}
}

func TestRunSliceEnvFileResolution(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}

	ls := setupSliceTestLocksmith(t, map[string]string{
		"db/creds": "my-db-pass-xyz-456",
	})

	tmpDir, err := os.MkdirTemp("", "locksmith-slice-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte("LOCKSMITH_SECRET_DB_PASS=db/creds\nREGULAR_VAR=visible_data\n"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	pyScript := `
import os, sys
fd = int(os.environ.get('LOCKSMITH_FD', '-1'))
if fd != 3:
    sys.exit(2)

# Check regular variable is present
if os.environ.get('REGULAR_VAR') != 'visible_data':
    sys.exit(3)

# Verify secret variable and secret content are NOT in os.environ
if 'LOCKSMITH_SECRET_DB_PASS' in os.environ:
    sys.exit(4)
if 'my-db-pass-xyz-456' in str(os.environ):
    sys.exit(5)

# Verify content from FD
with os.fdopen(fd) as f:
    if f.read() != 'my-db-pass-xyz-456':
        sys.exit(6)

sys.exit(0)
`

	// Empty sliceKey indicates slicing all resolved environment secrets
	code, err := ls.RunSlice([]string{"python3", "-c", pyScript}, "", envPath)
	if err != nil {
		t.Fatalf("RunSlice failed: %v", err)
	}
	if code != 0 {
		t.Fatalf("Python script returned non-zero code: %d", code)
	}
}

func TestRunSliceNonExistentSecret(t *testing.T) {
	ls := setupSliceTestLocksmith(t, map[string]string{})

	_, err := ls.RunSlice([]string{"true"}, "non/existent/secret", "")
	if err == nil {
		t.Fatal("Expected error when requesting non-existent secret, got nil")
	}
}
