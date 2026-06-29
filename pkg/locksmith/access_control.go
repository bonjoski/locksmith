package locksmith

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
)

// ErrAccessDenied is returned when a binary is not whitelisted to access a secret
var ErrAccessDenied = errors.New("access denied: calling binary is not whitelisted")

// Expose resolver as a variable to allow mocking in unit tests
var getCallingBinary = getCallingBinaryPath

// VerifyAccess checks if the calling binary is authorized to retrieve the given key
func (l *Locksmith) VerifyAccess(key string) error {
	// If AccessControl is not enabled or nil, bypass check
	if l.Config == nil || !l.Config.AccessControl.Enabled {
		return nil
	}

	// Resolve the absolute path of the calling binary
	callingPath, err := getCallingBinary()
	if err != nil {
		return fmt.Errorf("failed to resolve calling binary path: %w", err)
	}
	callingPath = filepath.Clean(callingPath)

	matchedAnyRule := false
	authorized := false

	// Evaluate all rules
	for _, rule := range l.Config.AccessControl.Rules {
		// Support glob pattern matching (e.g., "db/*")
		matched, err := path.Match(rule.Secret, key)
		if err != nil {
			continue // Skip malformed pattern rules
		}

		if matched {
			matchedAnyRule = true
			// Check if the calling binary matches one of the allowed binaries
			for _, allowed := range rule.AllowedBinaries {
				if filepath.Clean(allowed) == callingPath {
					authorized = true
					break
				}
			}
		}
	}

	// If the secret matched at least one access rule, but the calling binary
	// was not whitelisted in any of the matching rules, deny access.
	if matchedAnyRule && !authorized {
		return ErrAccessDenied
	}

	return nil
}
