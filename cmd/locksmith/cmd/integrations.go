package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/spf13/cobra"
)

var integrationsCmd = &cobra.Command{
	Use:   "integrations",
	Short: "Hardening tools for CLI integrations",
}

const integrationMigrateSecretTTL = 30 * 24 * time.Hour

var integrationsDoctorPaths []string
var integrationsAliasShell string

var integrationsAliasesCmd = &cobra.Command{
	Use:   "aliases [integration|all]",
	Short: "Show alias suggestions and missing alias support by integration",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := "all"
		if len(args) == 1 {
			target = args[0]
		}

		targets := integrationDoctorTargets(target)
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Integration alias support:")
		shellName := normalizedAliasShell(integrationsAliasShell)
		for _, name := range targets {
			if aliasCmd, ok := integrationExecAliasCommand(name, shellName); ok {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "- %s: built-in (suggestion: %s)\n", name, aliasCmd)
				continue
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "- %s: no built-in alias yet\n", name)
		}
		return nil
	},
}

var integrationsDoctorCmd = &cobra.Command{
	Use:   "doctor [integration|all]",
	Short: "Scan integration config files for plaintext token fields",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := "all"
		if len(args) == 1 {
			target = args[0]
		}

		summary, findings, err := integrationDoctorReport(target, integrationsDoctorPaths)
		if err != nil {
			return err
		}

		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Integration hardening report:")
		for _, line := range summary {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "- %s\n", line)
		}

		if len(findings) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No plaintext integration tokens detected.")
			for _, note := range integrationDoctorNotes(target) {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "- %s\n", note)
			}
			return nil
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Detected %d plaintext token field(s):\n", len(findings))
		for _, finding := range findings {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "- PLAINTEXT [%s] %s (%s)\n", finding.Integration, finding.FilePath, finding.KeyPath)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Run 'locksmith integrations scrub <integration|all>' to remove these fields.")
		return nil
	},
}

var integrationsMigrateCmd = &cobra.Command{
	Use:   "migrate [integration|all]",
	Short: "Import known plaintext integration secrets into Locksmith, then scrub them",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := "all"
		if len(args) == 1 {
			target = args[0]
		}

		targets, err := integrationMigrateTargets(target)
		if err != nil {
			return err
		}

		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Integration migration report:")
		for _, name := range targets {
			stored, missing, err := migrateIntegrationSecrets(name)
			if err != nil {
				return err
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "- %s: stored %d secret(s)\n", name, len(stored))
			for _, k := range stored {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  * %s\n", k)
			}
			for _, m := range missing {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  * missing source value for %s\n", m)
			}
		}

		missing, err := integrationScrubPreflightMissingSecrets(target)
		if err != nil {
			return err
		}
		if len(missing) > 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "")
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Migration completed, but scrub is still blocked due to missing required Locksmith secret(s):")
			for _, line := range missing {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "- %s\n", line)
			}
			return fmt.Errorf("migrate incomplete: missing required Locksmith secret(s)")
		}

		removed, updatedFiles, err := ls.ScrubIntegrationPlaintextTokens(target)
		if err != nil {
			return err
		}

		if len(removed) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "")
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No plaintext token fields found to scrub.")
			return nil
		}

		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "")
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Removed %d plaintext token field(s) across %d file(s).\n", len(removed), len(updatedFiles))
		for _, finding := range removed {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "- [%s] %s (%s)\n", finding.Integration, finding.FilePath, finding.KeyPath)
		}

		aliasLines := integrationAliasSuggestionLines(removed, normalizedAliasShell("auto"))
		if len(aliasLines) > 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "")
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Suggested aliases (optional, shell-aware):")
			for _, line := range aliasLines {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "- %s\n", line)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Add one or more to your shell rc file to make Locksmith-backed usage easier to remember.")
		}

		return nil
	},
}

var integrationsScrubCmd = &cobra.Command{
	Use:   "scrub [integration|all]",
	Short: "Remove known plaintext token fields from integration config files",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := "all"
		if len(args) == 1 {
			target = args[0]
		}

		missing, err := integrationScrubPreflightMissingSecrets(target)
		if err != nil {
			return err
		}
		if len(missing) > 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Scrub blocked to prevent auth lockout.")
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Missing required Locksmith secret(s):")
			for _, line := range missing {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "- %s\n", line)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "After importing the secret(s), run scrub again.")
			return fmt.Errorf("scrub blocked: missing required Locksmith secret(s)")
		}

		removed, updatedFiles, err := ls.ScrubIntegrationPlaintextTokens(target)
		if err != nil {
			return err
		}

		if len(removed) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No plaintext token fields found to scrub.")
			return nil
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Removed %d plaintext token field(s) across %d file(s).\n", len(removed), len(updatedFiles))
		for _, finding := range removed {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "- [%s] %s (%s)\n", finding.Integration, finding.FilePath, finding.KeyPath)
		}

		aliasLines := integrationAliasSuggestionLines(removed, normalizedAliasShell("auto"))
		if len(aliasLines) > 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "")
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Suggested aliases (optional, shell-aware):")
			for _, line := range aliasLines {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "- %s\n", line)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Add one or more to your shell rc file to make Locksmith-backed usage easier to remember.")
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(integrationsCmd)
	integrationsCmd.AddCommand(integrationsDoctorCmd)
	integrationsCmd.AddCommand(integrationsScrubCmd)
	integrationsCmd.AddCommand(integrationsAliasesCmd)
	integrationsCmd.AddCommand(integrationsMigrateCmd)
	integrationsDoctorCmd.Flags().StringArrayVar(&integrationsDoctorPaths, "path", nil, "Additional file or directory path to scan (repeatable)")
	integrationsAliasesCmd.Flags().StringVar(&integrationsAliasShell, "shell", "auto", "Shell format for alias suggestions: auto|bash|zsh|fish|powershell|cmd")
}

func integrationDoctorNotes(target string) []string {
	normalized := strings.TrimSpace(strings.ToLower(target))
	if normalized != "" && normalized != "all" && normalized != "gh" {
		return nil
	}

	backend := detectGHAuthBackend()
	if backend == "keyring" {
		return []string{"gh auth appears to use keyring storage; no plaintext token is expected in gh config files."}
	}
	return nil
}

func detectGHAuthBackend() string {
	out, err := exec.Command("gh", "auth", "status").CombinedOutput() // #nosec G204 // fixed command and args
	if err != nil {
		return ""
	}
	return ghAuthBackendFromStatus(string(out))
}

func ghAuthBackendFromStatus(output string) string {
	if strings.Contains(strings.ToLower(output), "(keyring)") {
		return "keyring"
	}
	return ""
}

func integrationDoctorReport(target string, customPaths []string) ([]string, []locksmith.IntegrationPlaintextFinding, error) {
	targets := integrationDoctorTargets(target)
	summary := make([]string, 0, len(targets))
	findings := make([]locksmith.IntegrationPlaintextFinding, 0)

	for _, t := range targets {
		f, err := ls.FindIntegrationPlaintextTokensWithPaths(t, customPaths)
		if err != nil {
			return nil, nil, err
		}
		findings = append(findings, f...)

		if len(f) == 0 {
			summary = append(summary, fmt.Sprintf("%s: 0 plaintext token fields", t))
			continue
		}
		summary = append(summary, fmt.Sprintf("%s: %d plaintext token field(s)", t, len(f)))
	}

	return summary, findings, nil
}

func integrationDoctorTargets(target string) []string {
	normalized := strings.TrimSpace(strings.ToLower(target))
	if normalized == "" || normalized == "all" {
		targets := locksmith.SupportedIntegrationHardeningTargets()
		sort.Strings(targets)
		return targets
	}
	return []string{normalized}
}

func integrationAliasSuggestionLines(removed []locksmith.IntegrationPlaintextFinding, shellName string) []string {
	unique := make(map[string]struct{})
	for _, finding := range removed {
		name := strings.TrimSpace(strings.ToLower(finding.Integration))
		if name == "" {
			continue
		}
		unique[name] = struct{}{}
	}

	if len(unique) == 0 {
		return nil
	}

	integrations := make([]string, 0, len(unique))
	for name := range unique {
		integrations = append(integrations, name)
	}
	sort.Strings(integrations)

	lines := make([]string, 0, len(integrations))
	for _, name := range integrations {
		if cmd, ok := integrationExecAliasCommand(name, shellName); ok {
			lines = append(lines, cmd)
			continue
		}
		lines = append(lines, fmt.Sprintf("%s: no built-in 'locksmith exec %s' profile yet (configure in ~/.locksmith/config.yml if desired)", name, name))
	}

	return lines
}

func integrationScrubPreflightMissingSecrets(target string) ([]string, error) {
	findings, err := ls.FindIntegrationPlaintextTokens(target)
	if err != nil {
		return nil, err
	}
	if len(findings) == 0 {
		return nil, nil
	}

	listed, err := ls.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list existing Locksmith secrets for scrub preflight: %w", err)
	}
	existing := make(map[string]struct{}, len(listed))
	for key := range listed {
		existing[key] = struct{}{}
	}

	locksmithPath := "locksmith"
	if exe, err := os.Executable(); err == nil && strings.TrimSpace(exe) != "" {
		locksmithPath = exe
	}

	return buildScrubPreflightLines(findings, existing, locksmithPath), nil
}

func buildScrubPreflightLines(findings []locksmith.IntegrationPlaintextFinding, existing map[string]struct{}, locksmithPath string) []string {
	lines := make([]string, 0)
	seenRequirements := make(map[string]struct{})

	for _, finding := range findings {
		name := strings.TrimSpace(strings.ToLower(finding.Integration))
		if name == "" {
			continue
		}

		field := integrationFindingField(finding.KeyPath)
		requiredKey, importHint, ok := integrationRequiredVaultSecret(name, field, locksmithPath)
		if !ok {
			continue
		}

		reqID := name + "|" + requiredKey
		if _, seen := seenRequirements[reqID]; seen {
			continue
		}
		seenRequirements[reqID] = struct{}{}

		if _, exists := existing[requiredKey]; exists {
			continue
		}

		lines = append(lines, fmt.Sprintf("%s field '%s' requires Locksmith key '%s'. Import first: %s", name, field, requiredKey, importHint))
	}

	sort.Strings(lines)
	return lines
}

func integrationRequiredVaultSecret(name string, field string, locksmithPath string) (requiredKey string, importHint string, ok bool) {
	intName := strings.TrimSpace(strings.ToLower(name))
	f := strings.TrimSpace(strings.ToLower(field))

	if intName == "gh" {
		requiredKey = "github/gh/token"
		importHint = fmt.Sprintf("command gh auth token | %q add %s --type token --owner-app github --source-url https://github.com", locksmithPath, requiredKey)
		return requiredKey, importHint, true
	}

	if intName == "glab" {
		switch f {
		case "oauth2_refresh_token", "refresh_token":
			requiredKey = "gitlab/glab/oauth2_refresh_token"
			importHint = fmt.Sprintf("manual step: add token to Locksmith first with %q add %s --type oauth_token --owner-app gitlab --source-url https://gitlab.com", locksmithPath, requiredKey)
			return requiredKey, importHint, true
		case "job_token":
			requiredKey = "gitlab/glab/job_token"
			importHint = fmt.Sprintf("manual step: add token to Locksmith first with %q add %s --type token --owner-app gitlab --source-url https://gitlab.com", locksmithPath, requiredKey)
			return requiredKey, importHint, true
		default:
			requiredKey = "gitlab/glab/token"
			importHint = fmt.Sprintf("command glab auth token | %q add %s --type oauth_token --owner-app gitlab --source-url https://gitlab.com", locksmithPath, requiredKey)
			return requiredKey, importHint, true
		}
	}

	if intName == "acli" {
		switch f {
		case "refresh_token":
			requiredKey = "atlassian/acli/oauth2_refresh_token"
			importHint = fmt.Sprintf("manual step: add token to Locksmith first with %q add %s --type oauth_token --owner-app atlassian --source-url https://api.atlassian.com", locksmithPath, requiredKey)
			return requiredKey, importHint, true
		case "id_token":
			requiredKey = "atlassian/acli/id_token"
			importHint = fmt.Sprintf("manual step: add token to Locksmith first with %q add %s --type oauth_token --owner-app atlassian --source-url https://api.atlassian.com", locksmithPath, requiredKey)
			return requiredKey, importHint, true
		case "client_secret", "secret", "password", "private_key", "privatekey", "credential", "credentials":
			requiredKey = "atlassian/acli/secret"
			importHint = fmt.Sprintf("manual step: add secret to Locksmith first with %q add %s --type token --owner-app atlassian --source-url https://api.atlassian.com", locksmithPath, requiredKey)
			return requiredKey, importHint, true
		default:
			requiredKey = "atlassian/acli/token"
			importHint = fmt.Sprintf("manual step: add token to Locksmith first with %q add %s --type oauth_token --owner-app atlassian --source-url https://api.atlassian.com", locksmithPath, requiredKey)
			return requiredKey, importHint, true
		}
	}

	return "", "", false
}

func integrationFindingField(keyPath string) string {
	v := strings.TrimSpace(strings.ToLower(keyPath))
	if v == "" {
		return "token"
	}

	open := strings.LastIndex(v, "(")
	close := strings.LastIndex(v, ")")
	if open >= 0 && close > open {
		inside := strings.TrimSpace(v[open+1 : close])
		if inside != "" {
			return inside
		}
	}

	parts := strings.Split(v, ".")
	last := strings.TrimSpace(parts[len(parts)-1])
	last = strings.TrimPrefix(last, "[")
	last = strings.TrimSuffix(last, "]")
	if last == "" {
		return "token"
	}
	return last
}

func normalizedAliasShell(raw string) string {
	v := strings.TrimSpace(strings.ToLower(raw))
	if v == "" || v == "auto" {
		if runtime.GOOS == "windows" {
			return "powershell"
		}
		return "bash"
	}
	supported := map[string]struct{}{
		"bash":       {},
		"zsh":        {},
		"fish":       {},
		"powershell": {},
		"cmd":        {},
	}
	if _, ok := supported[v]; ok {
		return v
	}
	if runtime.GOOS == "windows" {
		return "powershell"
	}
	return "bash"
}

func integrationExecAliasCommand(name string, shellName string) (string, bool) {
	intName := strings.TrimSpace(strings.ToLower(name))
	if intName == "" {
		return "", false
	}
	if intName != "acli" && intName != "gh" && intName != "glab" {
		return "", false
	}

	shell := normalizedAliasShell(shellName)
	target := fmt.Sprintf("locksmith exec %s --", intName)

	switch shell {
	case "fish":
		return fmt.Sprintf("abbr -a %s '%s'", intName, target), true
	case "powershell":
		return fmt.Sprintf("function global:%s { locksmith exec %s -- $args }", intName, intName), true
	case "cmd":
		return fmt.Sprintf("doskey %s=locksmith exec %s -- $*", intName, intName), true
	default: // bash, zsh
		return fmt.Sprintf("alias %s='%s'", intName, target), true
	}
}

func integrationMigrateTargets(target string) ([]string, error) {
	normalized := strings.TrimSpace(strings.ToLower(target))
	supported := []string{"acli", "gh", "glab"}
	if normalized == "" || normalized == "all" {
		return supported, nil
	}
	for _, s := range supported {
		if normalized == s {
			return []string{normalized}, nil
		}
	}
	return nil, fmt.Errorf("unsupported integration '%s' for migrate (supported: acli, gh, glab, all)", normalized)
}

func migrateIntegrationSecrets(name string) (stored []string, missing []string, err error) {
	switch strings.TrimSpace(strings.ToLower(name)) {
	case "gh":
		return migrateGHSecrets()
	case "glab":
		return migrateGLABSecrets()
	case "acli":
		return migrateACLISecrets()
	default:
		return nil, nil, fmt.Errorf("unsupported integration '%s' for migrate", name)
	}
}

func migrateGHSecrets() (stored []string, missing []string, err error) {
	tok, cmdErr := commandOutputTrim("gh", "auth", "token")
	if cmdErr != nil || tok == "" {
		return nil, []string{"github/gh/token"}, nil
	}
	if err := storeMigratedSecret("github/gh/token", tok, "token", "github", "https://github.com"); err != nil {
		return nil, nil, err
	}
	return []string{"github/gh/token"}, nil, nil
}

func migrateGLABSecrets() (stored []string, missing []string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve user home directory: %w", err)
	}

	paths := []string{
		filepath.Join(home, "Library", "Application Support", "glab-cli", "config.yml"),
		filepath.Join(home, ".config", "glab-cli", "config.yml"),
		filepath.Join(home, ".config", "glab-cli", "hosts.yml"),
	}

	tok, _ := firstScalarFromFiles(paths, "token")
	if tok != "" {
		if err := storeMigratedSecret("gitlab/glab/token", tok, "oauth_token", "gitlab", "https://gitlab.com"); err != nil {
			return nil, nil, err
		}
		stored = append(stored, "gitlab/glab/token")
	} else {
		missing = append(missing, "gitlab/glab/token")
	}

	refresh, _ := firstScalarFromFiles(paths, "oauth2_refresh_token")
	if refresh != "" {
		if err := storeMigratedSecret("gitlab/glab/oauth2_refresh_token", refresh, "oauth_token", "gitlab", "https://gitlab.com"); err != nil {
			return nil, nil, err
		}
		stored = append(stored, "gitlab/glab/oauth2_refresh_token")
	} else {
		missing = append(missing, "gitlab/glab/oauth2_refresh_token")
	}

	jobToken, _ := firstScalarFromFiles(paths, "job_token")
	if jobToken != "" {
		if err := storeMigratedSecret("gitlab/glab/job_token", jobToken, "token", "gitlab", "https://gitlab.com"); err != nil {
			return nil, nil, err
		}
		stored = append(stored, "gitlab/glab/job_token")
	}

	return stored, missing, nil
}

func migrateACLISecrets() (stored []string, missing []string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve user home directory: %w", err)
	}

	paths := []string{
		filepath.Join(home, ".config", "acli", "global_auth_config.yaml"),
		filepath.Join(home, ".config", "acli", "jira_config.yaml"),
		filepath.Join(home, ".config", "acli", "confluence_config.yaml"),
	}

	access, _ := firstScalarFromFiles(paths, "access_token")
	if access == "" {
		access, _ = firstScalarFromFiles(paths, "token")
	}
	if access == "" {
		access, _ = firstScalarFromFiles(paths, "oauth_token")
	}
	if access != "" {
		if err := storeMigratedSecret("atlassian/acli/token", access, "oauth_token", "atlassian", "https://api.atlassian.com"); err != nil {
			return nil, nil, err
		}
		stored = append(stored, "atlassian/acli/token")
	} else {
		missing = append(missing, "atlassian/acli/token")
	}

	refresh, _ := firstScalarFromFiles(paths, "refresh_token")
	if refresh != "" {
		if err := storeMigratedSecret("atlassian/acli/oauth2_refresh_token", refresh, "oauth_token", "atlassian", "https://api.atlassian.com"); err != nil {
			return nil, nil, err
		}
		stored = append(stored, "atlassian/acli/oauth2_refresh_token")
	}

	idToken, _ := firstScalarFromFiles(paths, "id_token")
	if idToken != "" {
		if err := storeMigratedSecret("atlassian/acli/id_token", idToken, "oauth_token", "atlassian", "https://api.atlassian.com"); err != nil {
			return nil, nil, err
		}
		stored = append(stored, "atlassian/acli/id_token")
	}

	return stored, missing, nil
}

func storeMigratedSecret(key string, value string, secretType string, ownerApp string, sourceURL string) error {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil
	}
	b := []byte(v)
	defer zeroBytesInPlace(b)
	return ls.SetWithContext(
		key,
		b,
		time.Now().Add(integrationMigrateSecretTTL),
		ls.Options.RequireBiometrics,
		locksmith.ParseSecretType(secretType),
		ownerApp,
		sourceURL,
		nil,
	)
}

func commandOutputTrim(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output() // #nosec G204 // fixed command and args
	if err != nil {
		return "", err
	}
	return trimScalarValue(string(out)), nil
}

func firstScalarFromFiles(paths []string, wantedKey string) (string, bool) {
	wanted := strings.ToLower(strings.TrimSpace(wantedKey))
	for _, p := range paths {
		v, ok := scalarFromFile(p, wanted)
		if ok {
			return v, true
		}
	}
	return "", false
}

func scalarFromFile(path string, wantedKey string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		key, val, ok := parseSimpleKVLine(s.Text())
		if !ok {
			continue
		}
		if key != wantedKey {
			continue
		}
		if val == "" {
			continue
		}
		return val, true
	}

	return "", false
}

func parseSimpleKVLine(line string) (key string, value string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	idx := strings.Index(trimmed, ":")
	if idx <= 0 {
		return "", "", false
	}

	key = strings.ToLower(strings.TrimSpace(trimmed[:idx]))
	value = trimScalarValue(trimmed[idx+1:])
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

func trimScalarValue(raw string) string {
	v := strings.TrimSpace(raw)
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	v = strings.TrimSuffix(v, ",")
	v = strings.TrimSpace(v)
	v = strings.Trim(v, "\"'`")
	v = strings.TrimSpace(v)
	v = strings.TrimRight(v, "\r\n")
	return v
}

func zeroBytesInPlace(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
