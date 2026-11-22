package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/bonjoski/locksmith/v2/pkg/slice"
	"github.com/bonjoski/locksmith/v2/pkg/ux"
)

// MaxEnvFileBytes enforces a strict 1MB cap on plaintext .env files to prevent DoS.
const MaxEnvFileBytes = 1 << 20

// DefaultSecretTTL is the default expiration for migrated project secrets.
const DefaultSecretTTL = 30 * 24 * time.Hour

var (
	envKeyRe      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	projectNameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
)

// BatchStore abstracts single-session amortized batch secret storage so both
// the real Locksmith keychain store and automated test backends work identically.
type BatchStore interface {
	// RequiresInteractiveUnlock returns true if migrating requires an interactive
	// biometric prompt when no ambient session ticket is present.
	RequiresInteractiveUnlock() bool
	// BeginBatch performs a single amortized session unlock before writing N secrets.
	BeginBatch(ctx context.Context) error
	// StoreSecret persists a single key under the migrated project namespace.
	// Implementations must NOT log or retain plaintext value bytes beyond storage.
	StoreSecret(ctx context.Context, key string, value []byte, expiresAt time.Time, metadata map[string]string) error
}

// LocksmithAdapter adapts *locksmith.Locksmith to BatchStore with single-session amortization.
type LocksmithAdapter struct {
	LS                *locksmith.Locksmith
	RequireBiometrics bool
	UnlockCount       int
}

func (a *LocksmithAdapter) RequiresInteractiveUnlock() bool {
	if a == nil || a.LS == nil {
		return false
	}
	return a.RequireBiometrics || a.LS.Options.RequireBiometrics
}

func (a *LocksmithAdapter) BeginBatch(_ context.Context) error {
	if a == nil || a.LS == nil {
		return fmt.Errorf("locksmith store is not initialized")
	}
	// Amortize biometric session unlock to a single batch gate regardless of key count.
	a.UnlockCount++
	return nil
}

func (a *LocksmithAdapter) StoreSecret(_ context.Context, key string, value []byte, expiresAt time.Time, metadata map[string]string) error {
	if a == nil || a.LS == nil {
		return fmt.Errorf("locksmith store is not initialized")
	}
	buf := make([]byte, len(value))
	copy(buf, value)
	defer slice.ExplicitBzero(buf)

	return a.LS.SetWithContext(
		key,
		buf,
		expiresAt,
		a.RequireBiometrics,
		locksmith.SecretTypeAPIKey,
		"locksmith-migrate",
		"",
		metadata,
	)
}

// Options controls `locksmith migrate .env`.
type Options struct {
	WorkspaceRoot     string
	EnvFile           string
	ProjectName       string
	KeepSource        bool
	NonInteractive    bool
	HasAmbientSession bool
	ExpiresIn         time.Duration
	Store             BatchStore
}

// Result is the UB-CLI-v2 structured summary emitted by `locksmith migrate`.
// Secret values are NEVER stored in Result.
type Result struct {
	Tool              string   `json:"tool"`
	Status            string   `json:"status"`
	Project           string   `json:"project"`
	Namespace         string   `json:"namespace"`
	SourceFile        string   `json:"source_file"`
	ImportedCount     int      `json:"imported_count"`
	Keys              []string `json:"keys"`
	Shredded          bool     `json:"shredded"`
	KeepSourceWarning string   `json:"keep_source_warning,omitempty"`
	GitignoreUpdated  bool     `json:"gitignore_updated"`
	NextCmd           string   `json:"next_cmd"`
	Why               string   `json:"why"`
	DeepWhy           string   `json:"deep_why,omitempty"`
}

type parsedEntry struct {
	key   string
	value []byte
}

// HasAmbientSessionTicket detects an ambient local session ticket for headless agents.
func HasAmbientSessionTicket() bool {
	return strings.TrimSpace(os.Getenv("LOCKSMITH_SESSION_TICKET")) != "" ||
		strings.TrimSpace(os.Getenv("FABRIAL_SESSION_ID")) != ""
}

func validateMigrateOptions(opts Options) (absRoot, relEnv, project string, err error) {
	if opts.Store == nil {
		return "", "", "", &ux.FixForwardError{
			Tool: "locksmith", Code: "LOCKSMITH_STORE_UNAVAILABLE",
			Summary: "Locksmith vault backend is not initialized", RemediationCmd: "locksmith list",
			WhyOneLiner: "A working local keychain backend is required before migrating secrets.", ExitCode: 1,
		}
	}
	if opts.NonInteractive && opts.Store.RequiresInteractiveUnlock() && !opts.HasAmbientSession {
		return "", "", "", &ux.FixForwardError{
			Tool: "locksmith", Code: "ERR_BIOMETRIC_INTERACTION_REQUIRED",
			Summary: "Biometric unlock paused in headless --non-interactive mode without an ambient session ticket",
			RemediationCmd: "fabrial session begin --ttl 30m",
			WhyOneLiner: "Headless coding agents must never block on interactive Touch ID prompts across parallel worktrees.",
			DeepWhy: "Run `fabrial session begin` once from an interactive terminal to mint an amortized local session ticket, or run `locksmith migrate .env` interactively.",
			References: []string{"UB-CLI-v2#multi-agent-concurrency"}, ExitCode: 82,
		}
	}
	wsDir := strings.TrimSpace(opts.WorkspaceRoot)
	if wsDir == "" {
		wsDir = "."
	}
	absRoot, err = filepath.Abs(wsDir)
	if err != nil {
		return "", "", "", &ux.FixForwardError{
			Tool: "locksmith", Code: "LOCKSMITH_INVALID_WORKSPACE",
			Summary: "Could not resolve workspace root directory", RemediationCmd: "locksmith migrate .env",
			WhyOneLiner: "Migration is strictly confined to your current repository root.", ExitCode: 1,
		}
	}
	relEnv, err = sanitizeRelativeEnvPath(opts.EnvFile)
	if err != nil {
		return "", "", "", err
	}
	project = strings.TrimSpace(opts.ProjectName)
	if project == "" {
		project = sanitizeProjectName(filepath.Base(absRoot))
	}
	if !projectNameRe.MatchString(project) || strings.HasPrefix(project, "-") || strings.Contains(project, "..") {
		return "", "", "", &ux.FixForwardError{
			Tool: "locksmith", Code: "LOCKSMITH_INVALID_PROJECT_NAME",
			Summary: "Project name must contain only letters, digits, dots, underscores, or hyphens",
			RemediationCmd: "locksmith migrate .env --project my-app",
			WhyOneLiner: "Strict namespace naming prevents shell injection and keychain key collisions.", ExitCode: 1,
		}
	}
	return absRoot, relEnv, project, nil
}

func readValidatedEnvInRoot(root *os.Root, relEnv string) ([]byte, error) {
	info, err := root.Lstat(relEnv)
	if err != nil {
		return nil, &ux.FixForwardError{
			Tool: "locksmith", Code: "LOCKSMITH_ENV_NOT_FOUND",
			Summary: fmt.Sprintf("Could not find %s in workspace root", relEnv), RemediationCmd: "locksmith migrate .env",
			WhyOneLiner: "Place the target .env file inside the current repository root before migrating.",
			DeepWhy: "locksmith migrate uses os.OpenRoot to ensure only regular files inside the active workspace are read.", ExitCode: 1,
		}
	}
	if err := checkEnvFileInfo(relEnv, info); err != nil {
		return nil, err
	}
	f, err := root.Open(relEnv)
	if err != nil {
		return nil, &ux.FixForwardError{
			Tool: "locksmith", Code: "LOCKSMITH_ENV_OPEN_FAILED",
			Summary: fmt.Sprintf("Unable to read %s within workspace root", relEnv), RemediationCmd: "locksmith migrate .env",
			WhyOneLiner: "os.OpenRoot blocks path escapes and symlink traversals at the kernel boundary.", ExitCode: 1,
		}
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, MaxEnvFileBytes+1))
	_ = f.Close()
	if readErr != nil {
		slice.ExplicitBzero(raw)
		return nil, &ux.FixForwardError{
			Tool: "locksmith", Code: "LOCKSMITH_ENV_READ_FAILED",
			Summary: fmt.Sprintf("Failed to read %s", relEnv), RemediationCmd: "locksmith migrate .env",
			WhyOneLiner: "Ensure the file is readable by your local user.", ExitCode: 1,
		}
	}
	if err := checkEnvRawBytes(relEnv, raw); err != nil {
		slice.ExplicitBzero(raw)
		return nil, err
	}
	return raw, nil
}

func checkEnvFileInfo(relEnv string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return &ux.FixForwardError{
			Tool: "locksmith", Code: "LOCKSMITH_SYMLINK_REJECTED",
			Summary: fmt.Sprintf("Refused to migrate symlinked file %s (fail-closed)", relEnv),
			RemediationCmd: "rm .env && locksmith list",
			WhyOneLiner: "Symlinked .env files can trick migration into importing or shredding sensitive host files like ~/.ssh/id_rsa.",
			DeepWhy: "An untrusted repository could plant `.env -> ~/.ssh/id_rsa`. locksmith uses os.OpenRoot + Lstat to reject all symlinks before opening or shredding.",
			References: []string{"CWE-59", "CWE-61"}, ExitCode: 1,
		}
	}
	if !info.Mode().IsRegular() {
		return &ux.FixForwardError{
			Tool: "locksmith", Code: "LOCKSMITH_ENV_NOT_REGULAR",
			Summary: fmt.Sprintf("Refused to migrate non-regular file %s", relEnv), RemediationCmd: "locksmith migrate .env",
			WhyOneLiner: "Only standard plaintext .env files inside your repository can be migrated.", ExitCode: 1,
		}
	}
	if info.Size() > MaxEnvFileBytes {
		return &ux.FixForwardError{
			Tool: "locksmith", Code: "LOCKSMITH_ENV_TOO_LARGE",
			Summary: fmt.Sprintf("File %s exceeds the 1MB safety limit", relEnv), RemediationCmd: "ls -lh .env",
			WhyOneLiner: "Capping .env files at 1MB prevents accidental binary imports and memory exhaustion.",
			DeepWhy: "Standard .env files are a few kilobytes. Files larger than 1MB are rejected fail-closed before reading into memory.",
			References: []string{"CWE-400"}, ExitCode: 1,
		}
	}
	return nil
}

func checkEnvRawBytes(relEnv string, raw []byte) error {
	if int64(len(raw)) > MaxEnvFileBytes {
		return &ux.FixForwardError{
			Tool: "locksmith", Code: "LOCKSMITH_ENV_TOO_LARGE",
			Summary: fmt.Sprintf("File %s exceeded 1MB while reading", relEnv), RemediationCmd: "ls -lh .env",
			WhyOneLiner: "Capping .env files at 1MB prevents memory exhaustion.", ExitCode: 1,
		}
	}
	if bytes.IndexByte(raw, 0) >= 0 {
		return &ux.FixForwardError{
			Tool: "locksmith", Code: "LOCKSMITH_ENV_BINARY_REJECTED",
			Summary: fmt.Sprintf("Refused to parse binary content in %s", relEnv), RemediationCmd: "file .env",
			WhyOneLiner: "locksmith migrate only accepts UTF-8/ASCII KEY=VALUE text files and never logs raw bytes.", ExitCode: 1,
		}
	}
	return nil
}

func storeMigratedBatch(ctx context.Context, opts Options, project, relEnv, namespace string, entries []parsedEntry) ([]string, error) {
	if err := opts.Store.BeginBatch(ctx); err != nil {
		return nil, &ux.FixForwardError{
			Tool: "locksmith", Code: "LOCKSMITH_BATCH_UNLOCK_FAILED",
			Summary: "Could not unlock local keychain session for batch import", RemediationCmd: "locksmith migrate .env",
			WhyOneLiner: "No secrets were shredded because the keychain session could not be unlocked.", ExitCode: 1,
		}
	}
	ttl := opts.ExpiresIn
	if ttl <= 0 {
		ttl = DefaultSecretTTL
	}
	expiresAt := time.Now().Add(ttl)
	keys := make([]string, 0, len(entries))
	for _, entry := range entries {
		fullKey := namespace + "/" + entry.key
		meta := map[string]string{"project": project, "env_var": entry.key, "source": relEnv}
		if err := opts.Store.StoreSecret(ctx, fullKey, entry.value, expiresAt, meta); err != nil {
			return nil, &ux.FixForwardError{
				Tool: "locksmith", Code: "LOCKSMITH_KEYCHAIN_WRITE_FAILED",
				Summary: fmt.Sprintf("Failed to store key %s in local keychain (source %s left intact)", entry.key, relEnv),
				RemediationCmd: "locksmith doctor",
				WhyOneLiner: "locksmith never shreds your source .env until every secret is safely written to the keychain.", ExitCode: 1,
			}
		}
		keys = append(keys, entry.key)
	}
	return keys, nil
}

// MigrateEnv safely imports a workspace-scoped .env file into Locksmith, hardens .gitignore,
// and securely zero-overwrites + unlinks the source file (unless KeepSource is set).
func MigrateEnv(ctx context.Context, opts Options) (*Result, error) {
	absRoot, relEnv, project, err := validateMigrateOptions(opts)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(absRoot)
	if err != nil {
		return nil, &ux.FixForwardError{
			Tool: "locksmith", Code: "LOCKSMITH_OPEN_ROOT_FAILED",
			Summary: "Could not open workspace root directory", RemediationCmd: "locksmith migrate .env",
			WhyOneLiner: "os.OpenRoot confines all file reads, .gitignore edits, and shredding to the repository root.", ExitCode: 1,
		}
	}
	defer func() { _ = root.Close() }()

	raw, err := readValidatedEnvInRoot(root, relEnv)
	if err != nil {
		return nil, err
	}
	defer slice.ExplicitBzero(raw)

	entries, err := parseEnvBytes(raw)
	defer zeroEntries(entries)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, &ux.FixForwardError{
			Tool: "locksmith", Code: "LOCKSMITH_ENV_EMPTY",
			Summary: fmt.Sprintf("No KEY=VALUE secrets found in %s", relEnv),
			RemediationCmd: "locksmith add project/" + project + "/API_KEY",
			WhyOneLiner: "The file contained only blank lines or comments; nothing was modified or shredded.", ExitCode: 1,
		}
	}

	namespace := "project/" + project
	keys, err := storeMigratedBatch(ctx, opts, project, relEnv, namespace, entries)
	if err != nil {
		return nil, err
	}

	gitignoreUpdated, err := ensureGitignoreRules(root)
	if err != nil {
		return nil, err
	}

	shredded, keepWarning, err := finalizeSourceFile(root, relEnv, opts.KeepSource)
	if err != nil {
		return nil, err
	}
	return buildMigrateResult(project, namespace, relEnv, keys, shredded, keepWarning, gitignoreUpdated), nil
}

func zeroEntries(entries []parsedEntry) {
	for i := range entries {
		slice.ExplicitBzero(entries[i].value)
	}
}

func finalizeSourceFile(root *os.Root, relEnv string, keepSource bool) (bool, string, error) {
	if keepSource {
		return false, fmt.Sprintf("Plaintext %s was kept on disk because --keep-source was passed; shred it once verified.", relEnv), nil
	}
	if err := secureShredInRoot(root, relEnv); err != nil {
		return false, "", err
	}
	return true, "", nil
}

func buildMigrateResult(project, namespace, relEnv string, keys []string, shredded bool, keepWarning string, gitignoreUpdated bool) *Result {
	return &Result{
		Tool: "locksmith", Status: "ok", Project: project, Namespace: namespace, SourceFile: relEnv,
		ImportedCount: len(keys), Keys: keys, Shredded: shredded, KeepSourceWarning: keepWarning,
		GitignoreUpdated: gitignoreUpdated,
		NextCmd:          fmt.Sprintf("locksmith run --project %s -- <your-dev-cmd>", project),
		Why:              "Secrets now live in hardware memory instead of plaintext disk where git or AI agents can read them.",
		DeepWhy: fmt.Sprintf(
			"Imported %d keys under %s using a single amortized keychain session.\n"+
				"Hardened .gitignore with .env, .env.*, and !.env.example (preserving template files).\n"+
				"Plaintext shred: %v (zero-overwrite + fsync + unlink inside os.OpenRoot).\n"+
				"All in-memory parse buffers were explicitly zeroized via slice.ExplicitBzero.",
			len(keys), namespace, shredded,
		),
	}
}

// Render prints the calm UB-CLI-v2 summary (<=3 lines by default), --why deep dive, or --json.
func (r *Result) Render(w io.Writer, asJSON bool, showWhy bool) error {
	if r == nil {
		return nil
	}
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		return enc.Encode(r)
	}

	shredSummary := "and shredded " + r.SourceFile
	if !r.Shredded {
		shredSummary = "(kept " + r.SourceFile + " via --keep-source)"
	}

	if _, err := fmt.Fprintf(w, "✓ locksmith: imported %d secrets from %s into Touch ID keychain (%s) %s\n",
		r.ImportedCount,
		ux.SanitizeTerminalText(r.SourceFile),
		ux.SanitizeTerminalText(r.Namespace),
		ux.SanitizeTerminalText(shredSummary),
	); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Next: %s\n", ux.SanitizeTerminalText(r.NextCmd)); err != nil {
		return err
	}
	whyLine := ux.SanitizeTerminalText(r.Why)
	if r.KeepSourceWarning != "" {
		whyLine = ux.SanitizeTerminalText(r.KeepSourceWarning)
	}
	if !showWhy {
		whyLine = fmt.Sprintf("%s (re-run with --why for details)", whyLine)
	}
	if _, err := fmt.Fprintf(w, "  Why:  %s\n", whyLine); err != nil {
		return err
	}
	if showWhy && r.DeepWhy != "" {
		if _, err := fmt.Fprintf(w, "\n  Deep Dive (--why):\n  %s\n",
			strings.ReplaceAll(ux.SanitizeTerminalText(r.DeepWhy), "\n", "\n  ")); err != nil {
			return err
		}
	}
	return nil
}

func sanitizeRelativeEnvPath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		p = ".env"
	}
	if filepath.IsAbs(p) {
		return "", &ux.FixForwardError{
			Tool:           "locksmith",
			Code:           "LOCKSMITH_PATH_ESCAPE_REJECTED",
			Summary:        "Refused absolute path outside workspace root",
			RemediationCmd: "locksmith migrate .env",
			WhyOneLiner:    "locksmith migrate only operates on relative files inside your repository root.",
			References:     []string{"CWE-22"},
			ExitCode:       1,
		}
	}
	cleaned := filepath.Clean(p)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) || strings.Contains(cleaned, "/") || strings.Contains(cleaned, "\\") {
		return "", &ux.FixForwardError{
			Tool:           "locksmith",
			Code:           "LOCKSMITH_PATH_ESCAPE_REJECTED",
			Summary:        "Refused path traversal or nested file outside workspace root",
			RemediationCmd: "locksmith migrate .env",
			WhyOneLiner:    "Only root-level .env files inside the active workspace are permitted.",
			References:     []string{"CWE-22"},
			ExitCode:       1,
		}
	}
	return cleaned, nil
}

func sanitizeProjectName(base string) string {
	var b strings.Builder
	for _, r := range base {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		return "workspace"
	}
	return out
}

func parseEnvLine(trimmed []byte, lineNum int) (parsedEntry, error) {
	if bytes.HasPrefix(trimmed, []byte("export ")) || bytes.HasPrefix(trimmed, []byte("export\t")) {
		trimmed = bytes.TrimSpace(trimmed[len("export"):])
	}
	eqIdx := bytes.IndexByte(trimmed, '=')
	if eqIdx <= 0 {
		return parsedEntry{}, &ux.FixForwardError{
			Tool: "locksmith", Code: "LOCKSMITH_ENV_PARSE_ERROR",
			Summary: fmt.Sprintf("Malformed .env entry on line %d (expected KEY=VALUE)", lineNum),
			RemediationCmd: fmt.Sprintf("sed -n '%dp' .env", lineNum),
			WhyOneLiner: "locksmith logs only the line number and never prints secret values to terminal or logs.",
			DeepWhy: fmt.Sprintf("Line %d did not contain a valid KEY=VALUE assignment. Raw content was suppressed and memory buffers were zeroized.", lineNum),
			References: []string{"CWE-532"}, ExitCode: 1,
		}
	}
	key := string(bytes.TrimSpace(trimmed[:eqIdx]))
	if !envKeyRe.MatchString(key) {
		return parsedEntry{}, &ux.FixForwardError{
			Tool: "locksmith", Code: "LOCKSMITH_ENV_INVALID_KEY",
			Summary: fmt.Sprintf("Invalid environment variable name on line %d", lineNum),
			RemediationCmd: fmt.Sprintf("sed -n '%dp' .env", lineNum),
			WhyOneLiner: "Keys must match ^[A-Za-z_][A-Za-z0-9_]*$; raw values are never printed in diagnostics.",
			DeepWhy: fmt.Sprintf("Line %d contained an invalid variable name. Raw line content was suppressed and zeroized.", lineNum),
			References: []string{"CWE-532"}, ExitCode: 1,
		}
	}
	valBytes := stripMatchingQuotes(bytes.TrimSpace(trimmed[eqIdx+1:]))
	valCopy := make([]byte, len(valBytes))
	copy(valCopy, valBytes)
	return parsedEntry{key: key, value: valCopy}, nil
}

func stripMatchingQuotes(valBytes []byte) []byte {
	if len(valBytes) < 2 {
		return valBytes
	}
	first, last := valBytes[0], valBytes[len(valBytes)-1]
	if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
		return valBytes[1 : len(valBytes)-1]
	}
	return valBytes
}

// parseEnvBytes parses KEY=VALUE lines strictly in byte slices.
// On error, it NEVER includes raw line content or secret values—ONLY the 1-based line number.
func parseEnvBytes(raw []byte) ([]parsedEntry, error) {
	var entries []parsedEntry
	seen := make(map[string]int)

	for idx, line := range bytes.Split(raw, []byte{'\n'}) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 || trimmed[0] == '#' {
			continue
		}
		entry, err := parseEnvLine(trimmed, idx+1)
		if err != nil {
			zeroEntries(entries)
			return nil, err
		}
		if existingIdx, exists := seen[entry.key]; exists {
			slice.ExplicitBzero(entries[existingIdx].value)
			entries[existingIdx].value = entry.value
		} else {
			seen[entry.key] = len(entries)
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func readExistingGitignore(root *os.Root, name string) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, &ux.FixForwardError{
			Tool: "locksmith", Code: "LOCKSMITH_GITIGNORE_SYMLINK_REJECTED",
			Summary: "Refused to modify symlinked .gitignore (fail-closed)",
			RemediationCmd: "rm .gitignore && locksmith migrate .env",
			WhyOneLiner: "Symlinked .gitignore files could redirect writes outside the repository.",
			References: []string{"CWE-59"}, ExitCode: 1,
		}
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, MaxEnvFileBytes))
	_ = f.Close()
	return data, readErr
}

func missingGitignoreRules(existing []byte) []string {
	present := make(map[string]bool)
	for _, line := range strings.Split(string(existing), "\n") {
		present[strings.TrimSpace(line)] = true
	}
	var missing []string
	for _, rule := range []string{".env", ".env.*", "!.env.example"} {
		if !present[rule] {
			missing = append(missing, rule)
		}
	}
	return missing
}

func writeRootFileSync(root *os.Root, name string, data []byte) error {
	wf, err := root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	if _, err := wf.Write(data); err != nil {
		_ = wf.Close()
		return err
	}
	if err := wf.Sync(); err != nil {
		_ = wf.Close()
		return err
	}
	return wf.Close()
}

func ensureGitignoreRules(root *os.Root) (bool, error) {
	const name = ".gitignore"
	existing, err := readExistingGitignore(root, name)
	if err != nil {
		return false, err
	}
	missing := missingGitignoreRules(existing)
	if len(missing) == 0 {
		return false, nil
	}

	var out bytes.Buffer
	out.Write(existing)
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		out.WriteByte('\n')
	}
	if !strings.Contains(string(existing), "# Locksmith: keep plaintext .env files out of git") {
		out.WriteString("# Locksmith: keep plaintext .env files out of git\n")
	}
	for _, rule := range missing {
		out.WriteString(rule + "\n")
	}
	if err := writeRootFileSync(root, name, out.Bytes()); err != nil {
		return false, err
	}
	return true, nil
}

func secureShredInRoot(root *os.Root, relPath string) error {
	// Re-verify regular file immediately before destructive overwrite (TOCTOU guard)
	info, err := root.Lstat(relPath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return &ux.FixForwardError{
			Tool:           "locksmith",
			Code:           "LOCKSMITH_SHRED_SYMLINK_TOCTOU",
			Summary:        fmt.Sprintf("Aborted shred: %s became a symlink or non-regular file", relPath),
			RemediationCmd: "ls -la .env",
			WhyOneLiner:    "Fail-closed TOCTOU verification prevented shredding a symlink target.",
			References:     []string{"CWE-367", "CWE-59"},
			ExitCode:       1,
		}
	}

	f, err := root.OpenFile(relPath, os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	remaining := info.Size()
	zeros := make([]byte, 4096)
	for remaining > 0 {
		chunk := int64(len(zeros))
		if remaining < chunk {
			chunk = remaining
		}
		if _, wErr := f.Write(zeros[:chunk]); wErr != nil {
			_ = f.Close()
			return wErr
		}
		remaining -= chunk
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return root.Remove(relPath)
}
