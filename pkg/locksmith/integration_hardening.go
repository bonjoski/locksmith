package locksmith

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type IntegrationPlaintextFinding struct {
	Integration string
	FilePath    string
	KeyPath     string
}

type integrationHardeningProfile struct {
	Name          string
	ConfigFiles   []string
	SensitiveKeys map[string]struct{}
}

var defaultIntegrationHardeningProfiles = map[string]integrationHardeningProfile{
	"ai": {
		Name: "ai",
		ConfigFiles: []string{
			".env",
			".env.local",
			".env.development",
			".env.production",
			".envrc",
			".claude.json",
			".config/claude/claude_desktop_config.json",
			".config/claude/.env",
			"Library/Application Support/Claude/claude_desktop_config.json",
			".cursor/mcp.json",
			".config/cursor/mcp.json",
			"Library/Application Support/Cursor/User/settings.json",
			"Library/Application Support/Code/User/settings.json",
			".continue/config.json",
			".continue/config.yaml",
			".aider.conf.yml",
			".config/aider/.aider.conf.yml",
			".config/openai/.env",
			".config/openai/config.json",
			".config/openai/apikey",
			".config/openai/auth.json",
			".config/anthropic/.env",
			".config/anthropic/config.json",
			".config/gemini/.env",
			".config/gemini/config.json",
		},
		SensitiveKeys: map[string]struct{}{
			"api_key":           {},
			"apikey":            {},
			"token":             {},
			"access_token":      {},
			"auth_token":        {},
			"openai_api_key":    {},
			"anthropic_api_key": {},
			"google_api_key":    {},
			"gemini_api_key":    {},
			"cohere_api_key":    {},
			"mistral_api_key":   {},
			"xai_api_key":       {},
			"provider_api_key":  {},
			"authorization":     {},
			"bearer_token":      {},
			"client_secret":     {},
			"oauth_token":       {},
			"refresh_token":     {},
			"session_token":     {},
		},
	},
	"acli": {
		Name: "acli",
		ConfigFiles: []string{
			".config/acli/global_auth_config.yaml",
			".config/acli/jira_config.yaml",
			".config/acli/confluence_config.yaml",
			".config/acli/admin_config.yaml",
			".config/acli/assets_config.yaml",
			".config/acli/brie_config.yaml",
			".config/acli/guard_config.yaml",
			".config/acli/rovodev_config.yaml",
		},
		SensitiveKeys: map[string]struct{}{
			"token":          {},
			"access_token":   {},
			"refresh_token":  {},
			"oauth_token":    {},
			"id_token":       {},
			"api_key":        {},
			"client_secret":  {},
			"password":       {},
			"secret":         {},
			"authorization":  {},
			"bearer_token":   {},
			"session_token":  {},
			"service_token":  {},
			"personal_token": {},
			"private_key":    {},
			"privatekey":     {},
			"credential":     {},
			"credentials":    {},
		},
	},
	"gh": {
		Name: "gh",
		ConfigFiles: []string{
			".config/gh/hosts.yml",
		},
		SensitiveKeys: map[string]struct{}{
			"oauth_token":  {},
			"token":        {},
			"access_token": {},
		},
	},
	"glab": {
		Name: "glab",
		ConfigFiles: []string{
			"Library/Application Support/glab-cli/config.yml",
			".config/glab-cli/config.yml",
			".config/glab-cli/hosts.yml",
		},
		SensitiveKeys: map[string]struct{}{
			"token":                 {},
			"oauth_token":           {},
			"access_token":          {},
			"personal_access_token": {},
			"job_token":             {},
			"oauth2_refresh_token":  {},
		},
	},
}

// SupportedIntegrationHardeningTargets returns all named targets accepted by integrations doctor/scrub.
func SupportedIntegrationHardeningTargets() []string {
	keys := make([]string, 0, len(defaultIntegrationHardeningProfiles))
	for k := range defaultIntegrationHardeningProfiles {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// FindIntegrationPlaintextTokens scans supported integration config files for plaintext token fields.
func (l *Locksmith) FindIntegrationPlaintextTokens(target string) ([]IntegrationPlaintextFinding, error) {
	return l.FindIntegrationPlaintextTokensWithPaths(target, nil)
}

// FindIntegrationPlaintextTokensWithPaths scans supported integration config files plus optional custom paths.
func (l *Locksmith) FindIntegrationPlaintextTokensWithPaths(target string, customPaths []string) ([]IntegrationPlaintextFinding, error) {
	profiles, err := resolveIntegrationHardeningProfiles(target)
	if err != nil {
		return nil, err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve user home directory: %w", err)
	}

	customFiles, err := resolveCustomScanFiles(customPaths)
	if err != nil {
		return nil, err
	}

	findings := make([]IntegrationPlaintextFinding, 0)
	for _, profile := range profiles {
		seen := make(map[string]struct{})
		defaultConfigFiles := integrationProfileConfigFiles(profile.Name, runtime.GOOS)
		candidates := make([]string, 0, len(defaultConfigFiles)+len(customFiles))
		for _, relPath := range defaultConfigFiles {
			fullPath := filepath.Clean(filepath.Join(home, relPath))
			if _, ok := seen[fullPath]; ok {
				continue
			}
			seen[fullPath] = struct{}{}
			candidates = append(candidates, fullPath)
		}
		for _, fullPath := range customFiles {
			if _, ok := seen[fullPath]; ok {
				continue
			}
			seen[fullPath] = struct{}{}
			candidates = append(candidates, fullPath)
		}

		for _, fullPath := range candidates {
			fileFindings, err := findPlaintextInFile(fullPath, profile)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return nil, err
			}
			findings = append(findings, fileFindings...)
		}
	}

	return findings, nil
}

func findPlaintextInFile(fullPath string, profile integrationHardeningProfile) ([]IntegrationPlaintextFinding, error) {
	doc, err := readYAMLDocument(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}

		rawFindings, rawErr := collectPlaintextFindingsFromRawFile(fullPath, profile)
		if rawErr != nil {
			return nil, fmt.Errorf("failed to parse %s config file '%s': %w", profile.Name, fullPath, err)
		}
		return rawFindings, nil
	}
	if !isStructuredConfigDocument(doc) {
		rawFindings, rawErr := collectPlaintextFindingsFromRawFile(fullPath, profile)
		if rawErr != nil {
			return nil, fmt.Errorf("failed to parse %s config file '%s' as raw key/value: %w", profile.Name, fullPath, rawErr)
		}
		return rawFindings, nil
	}

	findings := make([]IntegrationPlaintextFinding, 0)
	collectPlaintextFindings(doc, nil, profile, fullPath, &findings)
	return findings, nil
}

func resolveCustomScanFiles(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}

	files := make([]string, 0)
	seen := make(map[string]struct{})

	for _, raw := range paths {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}

		if strings.HasPrefix(p, "~/") {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("failed to resolve user home directory for custom scan path '%s': %w", raw, err)
			}
			p = filepath.Join(home, p[2:])
		}

		absPath, err := filepath.Abs(p)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve custom scan path '%s': %w", raw, err)
		}

		stat, err := os.Stat(absPath)
		if err != nil {
			return nil, fmt.Errorf("failed to access custom scan path '%s': %w", raw, err)
		}

		if stat.IsDir() {
			err := filepath.WalkDir(absPath, func(path string, d fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if d.IsDir() {
					return nil
				}
				clean := filepath.Clean(path)
				if _, ok := seen[clean]; ok {
					return nil
				}
				seen[clean] = struct{}{}
				files = append(files, clean)
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("failed to walk custom scan path '%s': %w", raw, err)
			}
			continue
		}

		clean := filepath.Clean(absPath)
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		files = append(files, clean)
	}

	sort.Strings(files)
	return files, nil
}

// ScrubIntegrationPlaintextTokens removes known plaintext token fields from supported integration config files.
func (l *Locksmith) ScrubIntegrationPlaintextTokens(target string) ([]IntegrationPlaintextFinding, []string, error) {
	profiles, err := resolveIntegrationHardeningProfiles(target)
	if err != nil {
		return nil, nil, err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve user home directory: %w", err)
	}

	removed := make([]IntegrationPlaintextFinding, 0)
	updatedFiles := make([]string, 0)
	for _, profile := range profiles {
		// AI target is scan-focused today; avoid mutating mixed JSON config formats in scrub.
		if profile.Name == "ai" {
			continue
		}
		for _, relPath := range integrationProfileConfigFiles(profile.Name, runtime.GOOS) {
			fullPath := filepath.Clean(filepath.Join(home, relPath))
			doc, err := readYAMLDocument(fullPath)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}

				rawRemoved, changed, rawErr := scrubPlaintextFieldsFromRawFile(fullPath, profile)
				if rawErr != nil {
					return nil, nil, fmt.Errorf("failed to parse %s config file '%s': %w", profile.Name, fullPath, err)
				}
				if changed {
					removed = append(removed, rawRemoved...)
					updatedFiles = append(updatedFiles, fullPath)
				}
				continue
			}
			if !isStructuredConfigDocument(doc) {
				rawRemoved, changed, rawErr := scrubPlaintextFieldsFromRawFile(fullPath, profile)
				if rawErr != nil {
					return nil, nil, fmt.Errorf("failed to parse %s config file '%s' as raw key/value: %w", profile.Name, fullPath, rawErr)
				}
				if changed {
					removed = append(removed, rawRemoved...)
					updatedFiles = append(updatedFiles, fullPath)
				}
				continue
			}

			fileRemoved := make([]IntegrationPlaintextFinding, 0)
			changed := scrubPlaintextFields(doc, nil, profile, fullPath, &fileRemoved)
			if !changed {
				continue
			}

			if err := writeYAMLDocument(fullPath, doc); err != nil {
				return nil, nil, fmt.Errorf("failed to write scrubbed config file '%s': %w", fullPath, err)
			}

			removed = append(removed, fileRemoved...)
			updatedFiles = append(updatedFiles, fullPath)
		}
	}

	return removed, updatedFiles, nil
}

func resolveIntegrationHardeningProfiles(target string) ([]integrationHardeningProfile, error) {
	normalized := strings.TrimSpace(strings.ToLower(target))
	if normalized == "" || normalized == "all" {
		keys := make([]string, 0, len(defaultIntegrationHardeningProfiles))
		for k := range defaultIntegrationHardeningProfiles {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		profiles := make([]integrationHardeningProfile, 0, len(keys))
		for _, k := range keys {
			profiles = append(profiles, defaultIntegrationHardeningProfiles[k])
		}
		return profiles, nil
	}

	profile, ok := defaultIntegrationHardeningProfiles[normalized]
	if !ok {
		supported := append(SupportedIntegrationHardeningTargets(), "all")
		return nil, fmt.Errorf("unsupported integration '%s' (supported: %s)", normalized, strings.Join(supported, ", "))
	}
	return []integrationHardeningProfile{profile}, nil
}

func integrationProfileConfigFiles(profileName string, goos string) []string {
	name := strings.TrimSpace(strings.ToLower(profileName))
	osName := strings.TrimSpace(strings.ToLower(goos))

	var out []string
	switch name {
	case "ai":
		// Project-local files are cross-platform and intentionally always included.
		out = append(out,
			".env",
			".env.local",
			".env.development",
			".env.production",
			".envrc",
			".claude.json",
			".cursor/mcp.json",
			".continue/config.json",
			".continue/config.yaml",
			".aider.conf.yml",
		)

		switch osName {
		case "windows":
			out = append(out,
				"AppData/Roaming/Claude/claude_desktop_config.json",
				"AppData/Roaming/Cursor/User/settings.json",
				"AppData/Roaming/Code/User/settings.json",
				"AppData/Roaming/aider/.aider.conf.yml",
				"AppData/Roaming/openai/.env",
				"AppData/Roaming/openai/config.json",
				"AppData/Roaming/openai/apikey",
				"AppData/Roaming/openai/auth.json",
				"AppData/Roaming/anthropic/.env",
				"AppData/Roaming/anthropic/config.json",
				"AppData/Roaming/gemini/.env",
				"AppData/Roaming/gemini/config.json",
			)
		case "darwin":
			out = append(out,
				".config/claude/claude_desktop_config.json",
				".config/claude/.env",
				"Library/Application Support/Claude/claude_desktop_config.json",
				".config/cursor/mcp.json",
				"Library/Application Support/Cursor/User/settings.json",
				"Library/Application Support/Code/User/settings.json",
				".config/aider/.aider.conf.yml",
				".config/openai/.env",
				".config/openai/config.json",
				".config/openai/apikey",
				".config/openai/auth.json",
				".config/anthropic/.env",
				".config/anthropic/config.json",
				".config/gemini/.env",
				".config/gemini/config.json",
			)
		default: // linux and other unix-like environments
			out = append(out,
				".config/claude/claude_desktop_config.json",
				".config/claude/.env",
				".config/cursor/mcp.json",
				".config/aider/.aider.conf.yml",
				".config/openai/.env",
				".config/openai/config.json",
				".config/openai/apikey",
				".config/openai/auth.json",
				".config/anthropic/.env",
				".config/anthropic/config.json",
				".config/gemini/.env",
				".config/gemini/config.json",
			)
		}

	case "acli":
		switch osName {
		case "windows":
			out = append(out,
				"AppData/Roaming/acli/global_auth_config.yaml",
				"AppData/Roaming/acli/jira_config.yaml",
				"AppData/Roaming/acli/confluence_config.yaml",
				"AppData/Roaming/acli/admin_config.yaml",
				"AppData/Roaming/acli/assets_config.yaml",
				"AppData/Roaming/acli/brie_config.yaml",
				"AppData/Roaming/acli/guard_config.yaml",
				"AppData/Roaming/acli/rovodev_config.yaml",
			)
		default:
			out = append(out,
				".config/acli/global_auth_config.yaml",
				".config/acli/jira_config.yaml",
				".config/acli/confluence_config.yaml",
				".config/acli/admin_config.yaml",
				".config/acli/assets_config.yaml",
				".config/acli/brie_config.yaml",
				".config/acli/guard_config.yaml",
				".config/acli/rovodev_config.yaml",
			)
		}

	case "gh":
		switch osName {
		case "windows":
			out = append(out, "AppData/Roaming/GitHub CLI/hosts.yml")
		default:
			out = append(out, ".config/gh/hosts.yml")
		}

	case "glab":
		switch osName {
		case "windows":
			out = append(out,
				"AppData/Roaming/glab-cli/config.yml",
				"AppData/Roaming/glab-cli/hosts.yml",
			)
		case "darwin":
			out = append(out,
				"Library/Application Support/glab-cli/config.yml",
				".config/glab-cli/config.yml",
				".config/glab-cli/hosts.yml",
			)
		default:
			out = append(out,
				".config/glab-cli/config.yml",
				".config/glab-cli/hosts.yml",
			)
		}
	}

	return uniquePreserveOrder(out)
}

func uniquePreserveOrder(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		v := filepath.Clean(strings.TrimSpace(item))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func readYAMLDocument(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var doc any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func writeYAMLDocument(path string, doc any) error {
	data, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}

	mode := os.FileMode(0600)
	if stat, err := os.Stat(path); err == nil {
		mode = stat.Mode().Perm()
	}
	return os.WriteFile(path, data, mode)
}

func collectPlaintextFindings(node any, pathParts []string, profile integrationHardeningProfile, filePath string, findings *[]IntegrationPlaintextFinding) {
	switch typed := node.(type) {
	case map[string]any:
		for k, v := range typed {
			nextPath := appendPath(pathParts, k)
			if keyLooksSensitive(profile.SensitiveKeys, k) && valueLooksPlaintextSecret(v) {
				*findings = append(*findings, IntegrationPlaintextFinding{
					Integration: profile.Name,
					FilePath:    filePath,
					KeyPath:     strings.Join(nextPath, "."),
				})
			}
			collectPlaintextFindings(v, nextPath, profile, filePath, findings)
		}
	case map[any]any:
		for k, v := range typed {
			keyName := fmt.Sprintf("%v", k)
			nextPath := appendPath(pathParts, keyName)
			if keyLooksSensitive(profile.SensitiveKeys, keyName) && valueLooksPlaintextSecret(v) {
				*findings = append(*findings, IntegrationPlaintextFinding{
					Integration: profile.Name,
					FilePath:    filePath,
					KeyPath:     strings.Join(nextPath, "."),
				})
			}
			collectPlaintextFindings(v, nextPath, profile, filePath, findings)
		}
	case []any:
		for i, item := range typed {
			collectPlaintextFindings(item, appendPath(pathParts, fmt.Sprintf("[%d]", i)), profile, filePath, findings)
		}
	}
}

func scrubPlaintextFields(node any, pathParts []string, profile integrationHardeningProfile, filePath string, removed *[]IntegrationPlaintextFinding) bool {
	changed := false

	switch typed := node.(type) {
	case map[string]any:
		for k, v := range typed {
			nextPath := appendPath(pathParts, k)
			if keyLooksSensitive(profile.SensitiveKeys, k) && valueLooksPlaintextSecret(v) {
				delete(typed, k)
				*removed = append(*removed, IntegrationPlaintextFinding{
					Integration: profile.Name,
					FilePath:    filePath,
					KeyPath:     strings.Join(nextPath, "."),
				})
				changed = true
				continue
			}
			if scrubPlaintextFields(v, nextPath, profile, filePath, removed) {
				changed = true
			}
		}
	case map[any]any:
		for k, v := range typed {
			keyName := fmt.Sprintf("%v", k)
			nextPath := appendPath(pathParts, keyName)
			if keyLooksSensitive(profile.SensitiveKeys, keyName) && valueLooksPlaintextSecret(v) {
				delete(typed, k)
				*removed = append(*removed, IntegrationPlaintextFinding{
					Integration: profile.Name,
					FilePath:    filePath,
					KeyPath:     strings.Join(nextPath, "."),
				})
				changed = true
				continue
			}
			if scrubPlaintextFields(v, nextPath, profile, filePath, removed) {
				changed = true
			}
		}
	case []any:
		for i, item := range typed {
			if scrubPlaintextFields(item, appendPath(pathParts, fmt.Sprintf("[%d]", i)), profile, filePath, removed) {
				changed = true
			}
		}
	}

	return changed
}

func appendPath(pathParts []string, next string) []string {
	out := make([]string, len(pathParts), len(pathParts)+1)
	copy(out, pathParts)
	out = append(out, next)
	return out
}

func isStructuredConfigDocument(doc any) bool {
	switch doc.(type) {
	case map[string]any, map[any]any, []any:
		return true
	default:
		return false
	}
}

func keyLooksSensitive(keys map[string]struct{}, key string) bool {
	_, ok := keys[normalizeScalar(key)]
	return ok
}

func valueLooksPlaintextSecret(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	trimmed := normalizeScalar(s)
	if trimmed == "" {
		return false
	}
	if strings.HasPrefix(trimmed, "locksmith://") {
		return false
	}
	return true
}

func collectPlaintextFindingsFromRawFile(path string, profile integrationHardeningProfile) ([]IntegrationPlaintextFinding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	findings := make([]IntegrationPlaintextFinding, 0)
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		key, value, ok := parseSimpleYAMLKV(scanner.Text())
		if !ok {
			continue
		}
		if !keyLooksSensitive(profile.SensitiveKeys, key) {
			continue
		}
		if !stringLooksPlaintextSecret(value) {
			continue
		}

		findings = append(findings, IntegrationPlaintextFinding{
			Integration: profile.Name,
			FilePath:    path,
			KeyPath:     fmt.Sprintf("line %d (%s)", lineNum, strings.TrimSpace(key)),
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

func scrubPlaintextFieldsFromRawFile(path string, profile integrationHardeningProfile) ([]IntegrationPlaintextFinding, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}

	lines := strings.Split(string(data), "\n")
	filtered := make([]string, 0, len(lines))
	removed := make([]IntegrationPlaintextFinding, 0)

	for i, line := range lines {
		key, value, ok := parseSimpleYAMLKV(line)
		if ok && keyLooksSensitive(profile.SensitiveKeys, key) && stringLooksPlaintextSecret(value) {
			removed = append(removed, IntegrationPlaintextFinding{
				Integration: profile.Name,
				FilePath:    path,
				KeyPath:     fmt.Sprintf("line %d (%s)", i+1, strings.TrimSpace(key)),
			})
			continue
		}
		filtered = append(filtered, line)
	}

	if len(removed) == 0 {
		return nil, false, nil
	}

	mode := os.FileMode(0600)
	if stat, err := os.Stat(path); err == nil {
		mode = stat.Mode().Perm()
	}

	out := strings.Join(filtered, "\n")
	if err := os.WriteFile(path, []byte(out), mode); err != nil {
		return nil, false, err
	}

	return removed, true, nil
}

func parseSimpleYAMLKV(line string) (key string, value string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	if strings.HasPrefix(strings.ToLower(trimmed), "export ") {
		trimmed = strings.TrimSpace(trimmed[len("export "):])
	}

	sep := ":"
	idx := strings.Index(trimmed, sep)
	if eqIdx := strings.Index(trimmed, "="); eqIdx > 0 && (idx < 0 || eqIdx < idx) {
		sep = "="
		idx = eqIdx
	}
	if idx <= 0 {
		return "", "", false
	}

	key = strings.TrimSpace(trimmed[:idx])
	value = strings.TrimSpace(trimmed[idx+1:])
	if sep == "=" {
		if c := strings.Index(value, " #"); c >= 0 {
			value = strings.TrimSpace(value[:c])
		}
	}
	if key == "" {
		return "", "", false
	}

	return key, value, true
}

func stringLooksPlaintextSecret(value string) bool {
	trimmed := normalizeScalar(value)
	if trimmed == "" {
		return false
	}
	if strings.HasPrefix(trimmed, "locksmith://") {
		return false
	}
	return true
}

func normalizeScalar(s string) string {
	trimmed := strings.TrimSpace(s)
	trimmed = strings.TrimSuffix(trimmed, ",")
	trimmed = strings.TrimSpace(trimmed)
	trimmed = strings.Trim(trimmed, "\"'`")
	return strings.ToLower(strings.TrimSpace(trimmed))
}
