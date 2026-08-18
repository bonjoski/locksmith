package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

func seedEnvSecret(mc *mockCache, key, value string) {
	mc.secrets[key] = locksmith.Secret{
		Value:     []byte(value),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
}

func TestEnvCmd_NoConfig(t *testing.T) {
	outBuf, _ := setupTest()
	envNoCache = true

	rootCmd.SetArgs([]string{"env"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if outBuf.Len() != 0 {
		t.Errorf("expected no output when shell.env is empty, got: %q", outBuf.String())
	}
}

func TestEnvCmd_ExportsSecrets(t *testing.T) {
	outBuf, _ := setupTest()
	envNoCache = true
	envShell = "sh"

	mc := ls.Cache.(*mockCache)
	seedEnvSecret(mc, "api/key", "supersecret")
	seedEnvSecret(mc, "db/password", "hunter2")

	cfg.Shell = locksmith.ShellConfig{
		Env: map[string]string{
			"MY_API_KEY":  "locksmith://api/key",
			"DB_PASSWORD": "locksmith://db/password",
		},
	}
	ls.Config = cfg

	rootCmd.SetArgs([]string{"env"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := outBuf.String()
	if !strings.Contains(out, "export MY_API_KEY='supersecret'") {
		t.Errorf("expected MY_API_KEY export, got: %q", out)
	}
	if !strings.Contains(out, "export DB_PASSWORD='hunter2'") {
		t.Errorf("expected DB_PASSWORD export, got: %q", out)
	}
}

func TestEnvCmd_FishOutput(t *testing.T) {
	outBuf, _ := setupTest()
	envNoCache = true
	envShell = "fish"

	mc := ls.Cache.(*mockCache)
	seedEnvSecret(mc, "api/key", "supersecret")

	cfg.Shell = locksmith.ShellConfig{
		Env: map[string]string{
			"MY_API_KEY": "locksmith://api/key",
		},
	}
	ls.Config = cfg

	rootCmd.SetArgs([]string{"env"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := outBuf.String()
	if !strings.Contains(out, "set -gx MY_API_KEY") {
		t.Errorf("expected fish set -gx output, got: %q", out)
	}
}

func TestEnvCmd_QuotesSpecialChars(t *testing.T) {
	outBuf, _ := setupTest()
	envNoCache = true
	envShell = "sh"

	mc := ls.Cache.(*mockCache)
	seedEnvSecret(mc, "tricky/secret", "it's a secret")

	cfg.Shell = locksmith.ShellConfig{
		Env: map[string]string{
			"TRICKY": "locksmith://tricky/secret",
		},
	}
	ls.Config = cfg

	rootCmd.SetArgs([]string{"env"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := outBuf.String()
	if !strings.Contains(out, `export TRICKY='it'\''s a secret'`) {
		t.Errorf("expected single-quote escaped value, got: %q", out)
	}
}
