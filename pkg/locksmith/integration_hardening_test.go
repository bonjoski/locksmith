package locksmith

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeTestConfigFile(path string, content string) error {
	b := []byte(content)
	defer func() {
		for i := range b {
			b[i] = 0
		}
	}()
	return os.WriteFile(path, b, 0600)
}

func setTestHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	drive := filepath.VolumeName(home)
	rest := strings.TrimPrefix(home, drive)
	if drive != "" {
		t.Setenv("HOMEDRIVE", drive)
		t.Setenv("HOMEPATH", rest)
	}
}

func TestFindIntegrationPlaintextTokens(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	ghPath := filepath.Join(home, ".config", "gh", "hosts.yml")
	if err := os.MkdirAll(filepath.Dir(ghPath), 0755); err != nil {
		t.Fatalf("failed to create gh config dir: %v", err)
	}

	ghConfig := "github.com:\n  user: octocat\n  oauth_token: ghp_abc123\n  git_protocol: https\n"
	if err := writeTestConfigFile(ghPath, ghConfig); err != nil {
		t.Fatalf("failed to write gh config: %v", err)
	}

	ls := NewWithCache(&MockCache{secrets: make(map[string]Secret)})
	findings, err := ls.FindIntegrationPlaintextTokens("gh")
	if err != nil {
		t.Fatalf("FindIntegrationPlaintextTokens failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Integration != "gh" {
		t.Fatalf("expected gh integration finding, got %q", findings[0].Integration)
	}
	if !strings.Contains(findings[0].KeyPath, "oauth_token") {
		t.Fatalf("expected oauth_token path, got %q", findings[0].KeyPath)
	}
}

func TestScrubIntegrationPlaintextTokens(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	glabPath := filepath.Join(home, ".config", "glab-cli", "config.yml")
	if err := os.MkdirAll(filepath.Dir(glabPath), 0755); err != nil {
		t.Fatalf("failed to create glab config dir: %v", err)
	}

	glabConfig := "hosts:\n  gitlab.com:\n    user: octocat\n    token: glpat_abc123\n"
	if err := writeTestConfigFile(glabPath, glabConfig); err != nil {
		t.Fatalf("failed to write glab config: %v", err)
	}

	ls := NewWithCache(&MockCache{secrets: make(map[string]Secret)})
	removed, updated, err := ls.ScrubIntegrationPlaintextTokens("glab")
	if err != nil {
		t.Fatalf("ScrubIntegrationPlaintextTokens failed: %v", err)
	}
	if len(removed) != 1 {
		t.Fatalf("expected 1 removed field, got %d", len(removed))
	}
	if len(updated) != 1 {
		t.Fatalf("expected 1 updated file, got %d", len(updated))
	}

	data, err := os.ReadFile(glabPath)
	if err != nil {
		t.Fatalf("failed to read scrubbed glab config: %v", err)
	}
	if strings.Contains(string(data), "glpat_abc123") {
		t.Fatal("expected plaintext token to be removed from config file")
	}
	if strings.Contains(string(data), "token:") {
		t.Fatal("expected token key to be removed from config file")
	}

	findings, err := ls.FindIntegrationPlaintextTokens("glab")
	if err != nil {
		t.Fatalf("FindIntegrationPlaintextTokens after scrub failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings after scrub, got %d", len(findings))
	}
}

func TestFindIntegrationPlaintextTokensGlabMacOSPath(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	defaultPaths := integrationProfileConfigFiles("glab", runtime.GOOS)
	if len(defaultPaths) == 0 {
		t.Fatal("expected at least one glab default config path")
	}
	glabPath := filepath.Join(home, defaultPaths[0])
	if err := os.MkdirAll(filepath.Dir(glabPath), 0755); err != nil {
		t.Fatalf("failed to create glab config dir: %v", err)
	}

	glabConfig := "hosts:\n  gitlab.com:\n    user: octocat\n    token: glpat_abc123\n"
	if err := writeTestConfigFile(glabPath, glabConfig); err != nil {
		t.Fatalf("failed to write glab macOS config: %v", err)
	}

	ls := NewWithCache(&MockCache{secrets: make(map[string]Secret)})
	findings, err := ls.FindIntegrationPlaintextTokens("glab")
	if err != nil {
		t.Fatalf("FindIntegrationPlaintextTokens failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].FilePath != glabPath {
		t.Fatalf("expected finding in %q, got %q", glabPath, findings[0].FilePath)
	}
}

func TestIntegrationHardeningUnknownTarget(t *testing.T) {
	ls := NewWithCache(&MockCache{secrets: make(map[string]Secret)})
	if _, err := ls.FindIntegrationPlaintextTokens("nope"); err == nil {
		t.Fatal("expected unknown target to return error")
	}
	if _, _, err := ls.ScrubIntegrationPlaintextTokens("nope"); err == nil {
		t.Fatal("expected unknown target to return error")
	}
}

func TestSupportedIntegrationHardeningTargetsIncludesACLI(t *testing.T) {
	targets := SupportedIntegrationHardeningTargets()
	found := false
	for _, tname := range targets {
		if tname == "acli" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected acli in supported targets, got %v", targets)
	}
}

func TestSupportedIntegrationHardeningTargetsIncludesAI(t *testing.T) {
	targets := SupportedIntegrationHardeningTargets()
	found := false
	for _, tname := range targets {
		if tname == "ai" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ai in supported targets, got %v", targets)
	}
}

func TestFindIntegrationPlaintextTokensAIJSON(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	aiPath := filepath.Join(home, ".config", "claude", "claude_desktop_config.json")
	if err := os.MkdirAll(filepath.Dir(aiPath), 0755); err != nil {
		t.Fatalf("failed to create ai config dir: %v", err)
	}

	aiConfig := "{\n  \"api_key\": \"sk-ant-abc123\"\n}\n"
	if err := writeTestConfigFile(aiPath, aiConfig); err != nil {
		t.Fatalf("failed to write ai config: %v", err)
	}

	ls := NewWithCache(&MockCache{secrets: make(map[string]Secret)})
	findings, err := ls.FindIntegrationPlaintextTokens("ai")
	if err != nil {
		t.Fatalf("FindIntegrationPlaintextTokens(ai) failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 ai finding, got %d", len(findings))
	}
}

func TestFindIntegrationPlaintextTokensAIIgnoresLocksmithRefQuoted(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	aiPath := filepath.Join(home, ".config", "claude", "claude_desktop_config.json")
	if err := os.MkdirAll(filepath.Dir(aiPath), 0755); err != nil {
		t.Fatalf("failed to create ai config dir: %v", err)
	}

	aiConfig := "{\n  \"api_key\": \"locksmith://ai/claude/api_key\"\n}\n"
	if err := writeTestConfigFile(aiPath, aiConfig); err != nil {
		t.Fatalf("failed to write ai config: %v", err)
	}

	ls := NewWithCache(&MockCache{secrets: make(map[string]Secret)})
	findings, err := ls.FindIntegrationPlaintextTokens("ai")
	if err != nil {
		t.Fatalf("FindIntegrationPlaintextTokens(ai) failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no ai findings for locksmith reference, got %d", len(findings))
	}
}

func TestFindAndScrubIntegrationPlaintextTokensMalformedYAML(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	defaultPaths := integrationProfileConfigFiles("glab", runtime.GOOS)
	if len(defaultPaths) == 0 {
		t.Fatal("expected at least one glab default config path")
	}
	glabPath := filepath.Join(home, defaultPaths[0])
	if err := os.MkdirAll(filepath.Dir(glabPath), 0755); err != nil {
		t.Fatalf("failed to create glab config dir: %v", err)
	}

	malformed := "last_update_check_timestamp: !!null 2026-07-17T15:07:24-06:00\nhosts:\n  gitlab.com:\n    token: glpat_bad\n"
	if err := writeTestConfigFile(glabPath, malformed); err != nil {
		t.Fatalf("failed to write malformed config: %v", err)
	}

	ls := NewWithCache(&MockCache{secrets: make(map[string]Secret)})
	findings, err := ls.FindIntegrationPlaintextTokens("glab")
	if err != nil {
		t.Fatalf("FindIntegrationPlaintextTokens failed on malformed YAML: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding on malformed YAML, got %d", len(findings))
	}

	removed, updated, err := ls.ScrubIntegrationPlaintextTokens("glab")
	if err != nil {
		t.Fatalf("ScrubIntegrationPlaintextTokens failed on malformed YAML: %v", err)
	}
	if len(removed) != 1 || len(updated) != 1 {
		t.Fatalf("expected one removal and one updated file, got removed=%d updated=%d", len(removed), len(updated))
	}

	data, err := os.ReadFile(glabPath)
	if err != nil {
		t.Fatalf("failed to read scrubbed malformed config: %v", err)
	}
	if strings.Contains(string(data), "glpat_bad") {
		t.Fatal("expected token value to be scrubbed from malformed YAML file")
	}
}

func TestFindIntegrationPlaintextTokensAIEnvFile(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	envPath := filepath.Join(home, ".env")
	content := "OPENAI_API_KEY=sk-openai-abc123\n"
	if err := writeTestConfigFile(envPath, content); err != nil {
		t.Fatalf("failed to write .env file: %v", err)
	}

	ls := NewWithCache(&MockCache{secrets: make(map[string]Secret)})
	findings, err := ls.FindIntegrationPlaintextTokens("ai")
	if err != nil {
		t.Fatalf("FindIntegrationPlaintextTokens(ai) failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 ai finding from .env, got %d", len(findings))
	}
	if findings[0].FilePath != envPath {
		t.Fatalf("expected finding in %q, got %q", envPath, findings[0].FilePath)
	}
	if !strings.Contains(strings.ToLower(findings[0].KeyPath), "openai_api_key") {
		t.Fatalf("expected openai_api_key key path, got %q", findings[0].KeyPath)
	}
}

func TestFindIntegrationPlaintextTokensAIProviderEnvFile(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	providerPath := filepath.Join(home, ".config", "anthropic", ".env")
	if err := os.MkdirAll(filepath.Dir(providerPath), 0755); err != nil {
		t.Fatalf("failed to create anthropic config dir: %v", err)
	}
	content := "export ANTHROPIC_API_KEY=sk-ant-abc123\n"
	if err := writeTestConfigFile(providerPath, content); err != nil {
		t.Fatalf("failed to write provider env file: %v", err)
	}

	ls := NewWithCache(&MockCache{secrets: make(map[string]Secret)})
	findings, err := ls.FindIntegrationPlaintextTokens("ai")
	if err != nil {
		t.Fatalf("FindIntegrationPlaintextTokens(ai) failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 ai finding from provider env file, got %d", len(findings))
	}
	if findings[0].FilePath != providerPath {
		t.Fatalf("expected finding in %q, got %q", providerPath, findings[0].FilePath)
	}
	if !strings.Contains(strings.ToLower(findings[0].KeyPath), "anthropic_api_key") {
		t.Fatalf("expected anthropic_api_key key path, got %q", findings[0].KeyPath)
	}
}

func TestFindIntegrationPlaintextTokensWithCustomPathFile(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	customFile := filepath.Join(t.TempDir(), "ai.env")
	if err := writeTestConfigFile(customFile, "OPENAI_API_KEY=sk-openai-custom\n"); err != nil {
		t.Fatalf("failed to write custom ai file: %v", err)
	}

	ls := NewWithCache(&MockCache{secrets: make(map[string]Secret)})
	findings, err := ls.FindIntegrationPlaintextTokensWithPaths("ai", []string{customFile})
	if err != nil {
		t.Fatalf("FindIntegrationPlaintextTokensWithPaths(ai) failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from custom file, got %d", len(findings))
	}
	if findings[0].FilePath != customFile {
		t.Fatalf("expected finding in %q, got %q", customFile, findings[0].FilePath)
	}
}

func TestFindIntegrationPlaintextTokensWithCustomPathDirectory(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	customDir := t.TempDir()
	nestedDir := filepath.Join(customDir, "nested")
	if err := os.MkdirAll(nestedDir, 0755); err != nil {
		t.Fatalf("failed to create nested custom dir: %v", err)
	}
	customFile := filepath.Join(nestedDir, "claude.env")
	if err := writeTestConfigFile(customFile, "export ANTHROPIC_API_KEY=sk-ant-custom\n"); err != nil {
		t.Fatalf("failed to write nested custom ai file: %v", err)
	}

	ls := NewWithCache(&MockCache{secrets: make(map[string]Secret)})
	findings, err := ls.FindIntegrationPlaintextTokensWithPaths("ai", []string{customDir})
	if err != nil {
		t.Fatalf("FindIntegrationPlaintextTokensWithPaths(ai) failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from custom directory, got %d", len(findings))
	}
	if findings[0].FilePath != customFile {
		t.Fatalf("expected finding in %q, got %q", customFile, findings[0].FilePath)
	}
}

func TestIntegrationProfileConfigFilesWindows(t *testing.T) {
	gh := integrationProfileConfigFiles("gh", "windows")
	if len(gh) != 1 || gh[0] != filepath.Clean("AppData/Roaming/GitHub CLI/hosts.yml") {
		t.Fatalf("unexpected windows gh paths: %v", gh)
	}

	glab := integrationProfileConfigFiles("glab", "windows")
	if len(glab) == 0 {
		t.Fatalf("expected windows glab paths, got %v", glab)
	}
	joined := strings.Join(glab, "\n")
	if !strings.Contains(joined, filepath.Clean("AppData/Roaming/glab-cli/config.yml")) {
		t.Fatalf("expected windows glab config path, got %v", glab)
	}

	ai := integrationProfileConfigFiles("ai", "windows")
	joinedAI := strings.Join(ai, "\n")
	if !strings.Contains(joinedAI, filepath.Clean("AppData/Roaming/openai/config.json")) {
		t.Fatalf("expected windows ai openai path, got %v", ai)
	}
	if !strings.Contains(joinedAI, filepath.Clean(".env")) {
		t.Fatalf("expected project-level .env in windows ai paths, got %v", ai)
	}
}

func TestIntegrationProfileConfigFilesDarwinAndLinux(t *testing.T) {
	darwin := integrationProfileConfigFiles("glab", "darwin")
	joinedDarwin := strings.Join(darwin, "\n")
	if !strings.Contains(joinedDarwin, filepath.Clean("Library/Application Support/glab-cli/config.yml")) {
		t.Fatalf("expected darwin glab Library path, got %v", darwin)
	}

	linux := integrationProfileConfigFiles("glab", "linux")
	joinedLinux := strings.Join(linux, "\n")
	if strings.Contains(joinedLinux, filepath.Clean("Library/Application Support/glab-cli/config.yml")) {
		t.Fatalf("did not expect darwin-specific glab Library path on linux, got %v", linux)
	}
	if !strings.Contains(joinedLinux, filepath.Clean(".config/glab-cli/config.yml")) {
		t.Fatalf("expected linux glab config path, got %v", linux)
	}
}
