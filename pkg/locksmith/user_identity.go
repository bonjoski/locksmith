package locksmith

import (
	"fmt"
	"os"
	"os/user"
)

// UserIdentity represents the OS user context used to cryptographically bind
// encryption keys to the user identity, providing defense-in-depth beyond file permissions.
type UserIdentity struct {
	UID      string
	Username string
	HomeDir  string
}

// CurrentUserIdentity retrieves the current OS user identity with robust fallbacks
// for minimal environments, containers, or headless runtimes.
func CurrentUserIdentity() (UserIdentity, error) {
	var identity UserIdentity

	// 1. Primary lookup via standard library os/user
	if u, err := user.Current(); err == nil && u != nil {
		identity.UID = u.Uid
		identity.Username = u.Username
		identity.HomeDir = u.HomeDir
	}

	// 2. Fallbacks for UID
	if identity.UID == "" {
		identity.UID = getSystemUID()
	}

	// 3. Fallbacks for Username
	if identity.Username == "" {
		for _, envKey := range []string{"USER", "USERNAME", "LOGNAME"} {
			if v := os.Getenv(envKey); v != "" {
				identity.Username = v
				break
			}
		}
	}

	// 4. Fallbacks for HomeDir
	if identity.HomeDir == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			identity.HomeDir = home
		}
	}

	// Validate that at least UID or Username is available to prevent degraded defense
	if identity.UID == "" && identity.Username == "" {
		return UserIdentity{}, fmt.Errorf("failed to determine user identity (no UID or username found)")
	}

	return identity, nil
}
