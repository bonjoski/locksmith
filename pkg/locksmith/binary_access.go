package locksmith

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bonjoski/locksmith/v2/pkg/protocol"
)

func isHexDigest64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func matchPathRule(target, exePath, canonicalPath string) bool {
	if target == "" {
		return false
	}
	if exePath != "" && exePath == target {
		return true
	}
	if canonicalPath != "" {
		if targetCanon, err := filepath.EvalSymlinks(target); err == nil && targetCanon == canonicalPath {
			return true
		}
		if canonicalPath == target {
			return true
		}
	}
	return false
}

func matchesBinaryRule(rule, exePath, canonicalPath, exeHash string) bool {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return false
	}
	lower := strings.ToLower(rule)
	switch {
	case strings.HasPrefix(lower, "sha256:"):
		return exeHash != "" && strings.EqualFold(exeHash, rule)
	case isHexDigest64(rule):
		return exeHash != "" && strings.EqualFold(exeHash, "sha256:"+rule)
	case strings.HasPrefix(lower, "path:"):
		return matchPathRule(rule[5:], exePath, canonicalPath)
	default:
		return matchPathRule(rule, exePath, canonicalPath)
	}
}

func ruleListNeedsHash(rules []string) bool {
	for _, r := range rules {
		trimmed := strings.TrimSpace(r)
		if strings.HasPrefix(strings.ToLower(trimmed), "sha256:") || isHexDigest64(trimmed) {
			return true
		}
	}
	return false
}

func canonicalizeExePath(exePath string) string {
	if exePath == "" {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil && resolved != "" {
		return resolved
	}
	return exePath
}

func resolveExeHash(canonicalPath, exeHash string, allowList, denyList []string) (string, error) {
	if exeHash != "" || canonicalPath == "" || (!ruleListNeedsHash(denyList) && !ruleListNeedsHash(allowList)) {
		return exeHash, nil
	}
	h, err := protocol.HashFile(canonicalPath)
	if err != nil && len(allowList) > 0 && ruleListNeedsHash(allowList) {
		return "", fmt.Errorf("failed to hash binary %q for access control: %w", canonicalPath, err)
	}
	return h, nil
}

// CheckBinaryAccessForExecutable enforces binary allow/deny lists against a caller's
// kernel-resolved executable path and/or SHA-256 hash.
func CheckBinaryAccessForExecutable(exePath, exeHash string, allowList, denyList []string) error {
	if len(allowList) == 0 && len(denyList) == 0 {
		return nil
	}
	if exePath == "" && exeHash == "" {
		return fmt.Errorf("binary access control requires attested executable path or hash")
	}

	canonicalPath := canonicalizeExePath(exePath)
	var err error
	exeHash, err = resolveExeHash(canonicalPath, exeHash, allowList, denyList)
	if err != nil {
		return err
	}

	label := exePath
	if label == "" {
		label = exeHash
	}

	// Deny list takes precedence
	for _, d := range denyList {
		if matchesBinaryRule(d, exePath, canonicalPath, exeHash) {
			return fmt.Errorf("binary %s is explicitly denied by access control", label)
		}
	}

	// If an allow list is defined, the binary must match at least one entry
	if len(allowList) > 0 {
		for _, a := range allowList {
			if matchesBinaryRule(a, exePath, canonicalPath, exeHash) {
				return nil
			}
		}
		return fmt.Errorf("binary %s is not in allowed list", label)
	}

	return nil
}

func (l *Locksmith) checkBinaryAccessWithOptions(opts Options) error {
	allowList := opts.AllowBinaries
	denyList := opts.DenyBinaries
	if l != nil && l.Config != nil {
		if len(allowList) == 0 {
			allowList = l.Config.AccessControl.AllowBinaries
		}
		if len(denyList) == 0 {
			denyList = l.Config.AccessControl.DenyBinaries
		}
	}

	if len(allowList) == 0 && len(denyList) == 0 {
		return nil
	}

	// When peer identity is supplied (e.g. IPC / DaemonServer / LeaseManager),
	// ALWAYS evaluate the peer's kernel-attested executable path/hash rather than os.Executable().
	if opts.PeerInstalled || opts.PeerExePath != "" || opts.PeerExeHash != "" {
		return CheckBinaryAccessForExecutable(opts.PeerExePath, opts.PeerExeHash, allowList, denyList)
	}

	execPath, err := os.Executable()
	if err != nil {
		return err
	}
	return CheckBinaryAccessForExecutable(execPath, "", allowList, denyList)
}

// checkBinaryAccess enforces binary whitelisting before accessing secrets.
// It checks the deny list first, then the allow list (if provided).
func (l *Locksmith) checkBinaryAccess() error {
	if l == nil {
		return nil
	}
	return l.checkBinaryAccessWithOptions(l.Options)
}
