package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

func TestCredentialGet(t *testing.T) {
	outBuf, _ := setupTest()

	// Pre-seed some secrets into the mock cache/backend
	mc := ls.Cache.(*mockCache)
	_ = mc.Set("git/github.com/myuser", locksmith.Secret{
		Value:     []byte("password123"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}, locksmith.DefaultCacheTTL)

	_ = mc.Set("github/gh/token", locksmith.Secret{
		Value:     []byte("ghtokenxyz"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}, locksmith.DefaultCacheTTL)

	// Test 1: get exact match
	stdin := "protocol=https\nhost=github.com\nusername=myuser\n\n"
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetOut(outBuf)
	rootCmd.SetArgs([]string{"credential", "get"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Failed to execute credential get: %v", err)
	}

	outStr := outBuf.String()
	if !strings.Contains(outStr, "username=myuser") {
		t.Errorf("Expected username=myuser in output, got %q", outStr)
	}
	if !strings.Contains(outStr, "password=password123") {
		t.Errorf("Expected password=password123 in output, got %q", outStr)
	}

	// Direct lookup check
	directSecret, directErr := ls.GetWithMetadata("github/gh/token")
	t.Logf("Direct lookup of github/gh/token: secret=%+v, err=%v", directSecret, directErr)
	if directSecret != nil {
		t.Logf("Direct value: %q", string(directSecret.Value))
	}

	// Test 2: fallback to github/gh/token
	outBuf.Reset()
	stdin = "protocol=https\nhost=github.com\n\n"
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetOut(outBuf)
	rootCmd.SetArgs([]string{"credential", "get"})

	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("Failed to execute credential get: %v", err)
	}

	outStr = outBuf.String()
	t.Logf("Fallback test output: %q", outStr)
	// Since no username is in stdin, it falls back to github/gh/token.
	// Since it's github/gh/token, the username outputs as "oauth2".
	if !strings.Contains(outStr, "username=oauth2") {
		t.Errorf("Expected username=oauth2, got %q", outStr)
	}
	if !strings.Contains(outStr, "password=ghtokenxyz") {
		t.Errorf("Expected password=ghtokenxyz, got %q", outStr)
	}
}

func TestCredentialStore(t *testing.T) {
	_, _ = setupTest()

	stdin := "protocol=https\nhost=gitlab.com\nusername=gitlabuser\npassword=tokenabc\n\n"
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetArgs([]string{"credential", "store"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Failed to execute credential store: %v", err)
	}

	secret, err := ls.GetWithMetadata("git/gitlab.com/gitlabuser")
	if err != nil {
		t.Fatalf("Failed to retrieve stored secret: %v", err)
	}
	if secret == nil {
		t.Fatal("Secret was not stored")
		return
	}
	if string(secret.Value) != "tokenabc" {
		t.Errorf("Expected secret value tokenabc, got %q", string(secret.Value))
	}
	if secret.Metadata["username"] != "gitlabuser" {
		t.Errorf("Expected metadata username gitlabuser, got %q", secret.Metadata["username"])
	}
}

func TestCredentialErase(t *testing.T) {
	_, _ = setupTest()

	mc := ls.Cache.(*mockCache)
	_ = mc.Set("git/github.com/myuser", locksmith.Secret{
		Value: []byte("pass"),
	}, locksmith.DefaultCacheTTL)

	stdin := "protocol=https\nhost=github.com\nusername=myuser\n\n"
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetArgs([]string{"credential", "erase"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Failed to execute credential erase: %v", err)
	}

	secret, _ := mc.Get("git/github.com/myuser")
	if secret != nil {
		t.Error("Expected secret to be deleted, but it still exists")
	}
}

func TestAddCommandWithGitFlag(t *testing.T) {
	outBuf, _ := setupTest()

	// Test 1: add with host and username (2 args)
	stdin := "mypassword123\n"
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetOut(outBuf)
	rootCmd.SetArgs([]string{"add", "github.com", "mygituser", "--git"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Failed to execute add command with --git flag: %v", err)
	}

	secret, err := ls.GetWithMetadata("git/github.com/mygituser")
	if err != nil {
		t.Fatalf("Failed to retrieve stored git secret: %v", err)
	}
	if secret == nil {
		t.Fatal("Secret was not stored")
		return
	}
	if string(secret.Value) != "mypassword123" {
		t.Errorf("Expected mypassword123, got %q", string(secret.Value))
	}
	if secret.Metadata["username"] != "mygituser" {
		t.Errorf("Expected mygituser, got %q", secret.Metadata["username"])
	}

	// Test 2: add with host only (1 arg) and username prompted
	outBuf.Reset()
	_, _ = setupTest() // reset
	addGit = true      // setupTest resets it, so we must set it back to true
	stdin = "promptuser\npromptpassword\n"
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetOut(outBuf)
	rootCmd.SetArgs([]string{"add", "gitlab.com", "--git"})

	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("Failed to execute add command with --git flag: %v", err)
	}

	secret, err = ls.GetWithMetadata("git/gitlab.com/promptuser")
	if err != nil {
		t.Fatalf("Failed to retrieve stored git secret: %v", err)
	}
	if secret == nil {
		t.Fatal("Secret was not stored")
		return
	}
	if string(secret.Value) != "promptpassword" {
		t.Errorf("Expected promptpassword, got %q", string(secret.Value))
	}
	if secret.Metadata["username"] != "promptuser" {
		t.Errorf("Expected promptuser, got %q", secret.Metadata["username"])
	}
}
