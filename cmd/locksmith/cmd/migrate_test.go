package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/locksmith/v2/pkg/migrate"
)

func TestMigrateCommand_EndToEndWithMockBackend(t *testing.T) {
	outBuf, errBuf := setupTest()
	defer func() {
		showWhy = false
		nonInteractive = false
	}()

	ws := t.TempDir()
	canary := "sk-live-CANARY999"
	if err := os.WriteFile(filepath.Join(ws, ".env"), []byte("OPENAI_API_KEY="+canary+"\nSTRIPE_KEY=sk_test_123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"migrate", ".env", "--dir", ws, "--project", "demo-app", "--why"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("locksmith migrate failed: %v (stderr: %s)", err, errBuf.String())
	}

	out := outBuf.String()
	if !strings.Contains(out, "imported 2 secrets") || !strings.Contains(out, "project/demo-app") {
		t.Fatalf("unexpected migrate output:\n%s", out)
	}
	if !strings.Contains(out, "Deep Dive (--why):") {
		t.Fatalf("expected --why deep dive in output:\n%s", out)
	}
	if strings.Contains(out, canary) || strings.Contains(errBuf.String(), canary) {
		t.Fatalf("canary secret leaked into CLI output!")
	}
	if _, err := os.Stat(filepath.Join(ws, ".env")); !os.IsNotExist(err) {
		t.Fatalf("expected .env to be shredded after migrate")
	}

	// Verify JSON mode on second workspace
	outBuf, errBuf = setupTest()
	ws2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws2, ".env"), []byte("API_TOKEN=tok123\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rootCmd.SetArgs([]string{"migrate", ".env", "--dir", ws2, "--project", "json-app", "--json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("locksmith migrate --json failed: %v (stderr: %s)", err, errBuf.String())
	}
	var res migrate.Result
	if err := json.Unmarshal(outBuf.Bytes(), &res); err != nil {
		t.Fatalf("invalid JSON from migrate --json: %v (raw: %s)", err, outBuf.String())
	}
	if res.ImportedCount != 1 || res.Namespace != "project/json-app" || !res.Shredded {
		t.Fatalf("unexpected JSON result: %+v", res)
	}
}
