package cmd

import (
	"encoding/json"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

func seedTestSecret(key, val string) {
	sec := locksmith.Secret{
		Value:     []byte(val),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	mc := ls.Cache.(*mockCache)
	mc.secrets[key] = sec

	secData, _ := json.Marshal(sec)
	mb := &mockRunBackend{
		secrets: map[string][]byte{
			key: secData,
		},
	}
	ls.Backend = mb
}

func TestRunCommandWithSliceFlag(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("File descriptor inheritance (ExtraFiles / FD 3) is not supported on Windows")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available, skipping")
	}

	_, _ = setupTest()

	var capturedExitCode int
	originalExitFunc := exitFunc
	exitFunc = func(code int) {
		capturedExitCode = code
	}
	defer func() { exitFunc = originalExitFunc }()

	seedTestSecret("service/api_token", "super_secret_slice_token_123")

	pyScript := `
import os, sys
fd = int(os.environ.get('LOCKSMITH_FD', '-1'))
if fd != 3:
    sys.exit(2)
with os.fdopen(fd) as f:
    if f.read() != 'super_secret_slice_token_123':
        sys.exit(3)
sys.exit(0)
`

	rootCmd.SetArgs([]string{"run", "--slice", "service/api_token", "--", "python3", "-c", pyScript})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("run --slice failed: %v", err)
	}

	if capturedExitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", capturedExitCode)
	}
}

func TestSliceSubcommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("File descriptor inheritance (ExtraFiles / FD 3) is not supported on Windows")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available, skipping")
	}

	_, _ = setupTest()

	var capturedExitCode int
	originalExitFunc := exitFunc
	exitFunc = func(code int) {
		capturedExitCode = code
	}
	defer func() { exitFunc = originalExitFunc }()

	seedTestSecret("database/staging_pass", "p@ssword_from_slice_cmd")

	pyScript := `
import os, sys
fd = int(os.environ.get('LOCKSMITH_FD', '-1'))
if fd != 3:
    sys.exit(2)
with os.fdopen(fd) as f:
    if f.read() != 'p@ssword_from_slice_cmd':
        sys.exit(3)
sys.exit(0)
`

	rootCmd.SetArgs([]string{"slice", "database/staging_pass", "--", "python3", "-c", pyScript})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("slice subcommand failed: %v", err)
	}

	if capturedExitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", capturedExitCode)
	}
}
