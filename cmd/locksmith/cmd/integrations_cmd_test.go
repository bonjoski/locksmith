package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

func TestIntegrationsDoctorTooManyArgs(t *testing.T) {
	_, _ = setupTest()
	rootCmd.SetArgs([]string{"integrations", "doctor", "gh", "extra"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected integrations doctor to reject too many args")
	}
}

func TestIntegrationsScrubTooManyArgs(t *testing.T) {
	_, _ = setupTest()
	rootCmd.SetArgs([]string{"integrations", "scrub", "gh", "extra"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected integrations scrub to reject too many args")
	}
}

func TestGHAuthBackendFromStatusKeyring(t *testing.T) {
	status := `github.com
  ✓ Logged in to github.com account octocat (keyring)
  - Active account: true
`
	if got := ghAuthBackendFromStatus(status); got != "keyring" {
		t.Fatalf("expected keyring backend, got %q", got)
	}
}

func TestIntegrationDoctorNotesForNonGHTarget(t *testing.T) {
	notes := integrationDoctorNotes("glab")
	if len(notes) != 0 {
		t.Fatalf("expected no notes for glab-only target, got %v", notes)
	}
}

func TestIntegrationDoctorTargetsAllIncludesACLI(t *testing.T) {
	targets := integrationDoctorTargets("all")
	hasACLI := false
	for _, tname := range targets {
		if tname == "acli" {
			hasACLI = true
			break
		}
	}
	if !hasACLI {
		t.Fatalf("expected 'all' targets to include acli, got %v", targets)
	}
}

func TestIntegrationDoctorTargetsSingle(t *testing.T) {
	targets := integrationDoctorTargets("gLaB")
	if len(targets) != 1 || targets[0] != "glab" {
		t.Fatalf("expected [glab], got %v", targets)
	}
}

func TestIntegrationAliasSuggestionLinesKnownAndUnknown(t *testing.T) {
	removed := []locksmith.IntegrationPlaintextFinding{
		{Integration: "glab"},
		{Integration: "acli"},
		{Integration: "gh"},
	}

	lines := integrationAliasSuggestionLines(removed, "bash")
	if len(lines) != 3 {
		t.Fatalf("expected 3 suggestion lines, got %d (%v)", len(lines), lines)
	}

	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "alias gh='locksmith exec gh --'") {
		t.Fatalf("expected gh alias suggestion, got %v", lines)
	}
	if !strings.Contains(joined, "alias glab='locksmith exec glab --'") {
		t.Fatalf("expected glab alias suggestion, got %v", lines)
	}
	if !strings.Contains(joined, "alias acli='locksmith exec acli --'") {
		t.Fatalf("expected acli alias suggestion, got %v", lines)
	}
}

func TestIntegrationExecAliasCommand(t *testing.T) {
	if cmd, ok := integrationExecAliasCommand("gh", "bash"); !ok || cmd == "" {
		t.Fatal("expected gh alias command")
	}
	if cmd, ok := integrationExecAliasCommand("acli", "bash"); !ok || cmd == "" {
		t.Fatal("expected acli alias command")
	}
}

func TestIntegrationExecAliasCommandByShell(t *testing.T) {
	if cmd, ok := integrationExecAliasCommand("gh", "powershell"); !ok || !strings.Contains(cmd, "function global:gh") {
		t.Fatalf("expected powershell function alias, got ok=%v cmd=%q", ok, cmd)
	}
	if cmd, ok := integrationExecAliasCommand("gh", "cmd"); !ok || !strings.Contains(cmd, "doskey gh=") {
		t.Fatalf("expected cmd doskey alias, got ok=%v cmd=%q", ok, cmd)
	}
	if cmd, ok := integrationExecAliasCommand("gh", "fish"); !ok || !strings.Contains(cmd, "abbr -a gh") {
		t.Fatalf("expected fish abbr alias, got ok=%v cmd=%q", ok, cmd)
	}
}

func TestBuildScrubPreflightLinesMissingGLAB(t *testing.T) {
	findings := []locksmith.IntegrationPlaintextFinding{{Integration: "glab", KeyPath: "line 1 (token)"}}
	existing := map[string]struct{}{}
	lines := buildScrubPreflightLines(findings, existing, "/tmp/locksmith")
	if len(lines) != 1 {
		t.Fatalf("expected one preflight line, got %d (%v)", len(lines), lines)
	}
	if !strings.Contains(lines[0], "gitlab/glab/token") {
		t.Fatalf("expected required glab key in line, got %q", lines[0])
	}
	if !strings.Contains(lines[0], "command glab auth token") {
		t.Fatalf("expected glab import hint in line, got %q", lines[0])
	}
}

func TestBuildScrubPreflightLinesMissingGLABRefresh(t *testing.T) {
	findings := []locksmith.IntegrationPlaintextFinding{{Integration: "glab", KeyPath: "hosts.gitlab.com.oauth2_refresh_token"}}
	existing := map[string]struct{}{}
	lines := buildScrubPreflightLines(findings, existing, "/tmp/locksmith")
	if len(lines) != 1 {
		t.Fatalf("expected one preflight line, got %d (%v)", len(lines), lines)
	}
	if !strings.Contains(lines[0], "gitlab/glab/oauth2_refresh_token") {
		t.Fatalf("expected required glab refresh key in line, got %q", lines[0])
	}
}

func TestBuildScrubPreflightLinesSkipsWhenKeyExists(t *testing.T) {
	findings := []locksmith.IntegrationPlaintextFinding{{Integration: "gh", KeyPath: "line 1 (oauth_token)"}}
	existing := map[string]struct{}{"github/gh/token": {}}
	lines := buildScrubPreflightLines(findings, existing, "/tmp/locksmith")
	if len(lines) != 0 {
		t.Fatalf("expected no preflight lines when key exists, got %v", lines)
	}
}

func TestBuildScrubPreflightLinesMissingACLI(t *testing.T) {
	findings := []locksmith.IntegrationPlaintextFinding{{Integration: "acli", KeyPath: "line 3 (access_token)"}}
	existing := map[string]struct{}{}
	lines := buildScrubPreflightLines(findings, existing, "/tmp/locksmith")
	if len(lines) != 1 {
		t.Fatalf("expected one preflight line, got %d (%v)", len(lines), lines)
	}
	if !strings.Contains(lines[0], "atlassian/acli/token") {
		t.Fatalf("expected required acli key in line, got %q", lines[0])
	}
}

func TestIntegrationRequiredVaultSecret(t *testing.T) {
	key, hint, ok := integrationRequiredVaultSecret("gh", "oauth_token", "/tmp/locksmith")
	if !ok || key != "github/gh/token" || hint == "" {
		t.Fatalf("unexpected gh requirement tuple: ok=%v key=%q hint=%q", ok, key, hint)
	}
	if key, hint, ok := integrationRequiredVaultSecret("acli", "access_token", "/tmp/locksmith"); !ok || key != "atlassian/acli/token" || hint == "" {
		t.Fatalf("unexpected acli requirement tuple: ok=%v key=%q hint=%q", ok, key, hint)
	}
	if key, _, ok := integrationRequiredVaultSecret("glab", "oauth2_refresh_token", "/tmp/locksmith"); !ok || key != "gitlab/glab/oauth2_refresh_token" {
		t.Fatalf("unexpected glab refresh requirement tuple: ok=%v key=%q", ok, key)
	}
}

func TestIntegrationFindingField(t *testing.T) {
	if got := integrationFindingField("line 113 (oauth2_refresh_token)"); got != "oauth2_refresh_token" {
		t.Fatalf("expected oauth2_refresh_token, got %q", got)
	}
	if got := integrationFindingField("hosts.gitlab.com.token"); got != "token" {
		t.Fatalf("expected token, got %q", got)
	}
}

func TestIntegrationMigrateTargetsAll(t *testing.T) {
	targets, err := integrationMigrateTargets("all")
	if err != nil {
		t.Fatalf("integrationMigrateTargets(all) failed: %v", err)
	}
	if len(targets) != 3 {
		t.Fatalf("expected 3 migrate targets, got %d (%v)", len(targets), targets)
	}
}

func TestIntegrationMigrateTargetsInvalid(t *testing.T) {
	if _, err := integrationMigrateTargets("ai"); err == nil {
		t.Fatal("expected unsupported migrate target to fail")
	}
}

func TestParseSimpleKVLine(t *testing.T) {
	key, val, ok := parseSimpleKVLine("  oauth2_refresh_token: \"abc123\"  ")
	if !ok {
		t.Fatal("expected parseSimpleKVLine to parse valid line")
	}
	if key != "oauth2_refresh_token" || val != "abc123" {
		t.Fatalf("unexpected parse result key=%q val=%q", key, val)
	}
}

func TestIntegrationsAliasesTooManyArgs(t *testing.T) {
	_, _ = setupTest()
	rootCmd.SetArgs([]string{"integrations", "aliases", "gh", "extra"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected integrations aliases to reject too many args")
	}
}

func TestIntegrationsAliasesAllShowsMissingAndBuiltIn(t *testing.T) {
	outBuf, _ := setupTest()
	rootCmd.SetArgs([]string{"integrations", "aliases", "all"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("integrations aliases all failed: %v", err)
	}

	out := outBuf.String()
	if !strings.Contains(out, "gh: built-in") {
		t.Fatalf("expected gh built-in alias output, got: %s", out)
	}
	if !strings.Contains(out, "glab: built-in") {
		t.Fatalf("expected glab built-in alias output, got: %s", out)
	}
	if !strings.Contains(out, "acli: built-in") {
		t.Fatalf("expected acli built-in alias output, got: %s", out)
	}

	// Reset output for other tests defensively.
	rootCmd.SetOut(new(bytes.Buffer))
}

func TestIntegrationsAliasesShellFlag(t *testing.T) {
	outBuf, _ := setupTest()
	rootCmd.SetArgs([]string{"integrations", "aliases", "gh", "--shell", "powershell"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("integrations aliases --shell powershell failed: %v", err)
	}

	out := outBuf.String()
	if !strings.Contains(out, "function global:gh") {
		t.Fatalf("expected powershell alias output, got: %s", out)
	}
}

func TestIntegrationsDoctorWithCustomPathFlag(t *testing.T) {
	outBuf, _ := setupTest()

	customFile := filepath.Join(t.TempDir(), "ai.env")
	if err := os.WriteFile(customFile, []byte("OPENAI_API_KEY=sk-openai-flag\n"), 0600); err != nil {
		t.Fatalf("failed to write custom path file: %v", err)
	}

	rootCmd.SetArgs([]string{"integrations", "doctor", "ai", "--path", customFile})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("integrations doctor ai --path failed: %v", err)
	}

	out := outBuf.String()
	if !strings.Contains(out, "Detected 1 plaintext token field(s)") {
		t.Fatalf("expected one plaintext finding in output, got: %s", out)
	}
	if !strings.Contains(out, customFile) {
		t.Fatalf("expected output to include custom file path %q, got: %s", customFile, out)
	}
	if !strings.Contains(strings.ToLower(out), "openai_api_key") {
		t.Fatalf("expected output to include openai_api_key finding, got: %s", out)
	}
}
