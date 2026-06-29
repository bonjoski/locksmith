package locksmith

import (
	"errors"
	"testing"
)

func TestVerifyAccess(t *testing.T) {
	// Backup original resolver
	origResolver := getCallingBinary
	defer func() { getCallingBinary = origResolver }()

	// Test configuration
	cfg := &Config{
		AccessControl: AccessControlConfig{
			Enabled: true,
			Rules: []AccessControlRule{
				{
					Secret: "db/password",
					AllowedBinaries: []string{
						"/usr/bin/postgres",
						"/usr/local/bin/app",
					},
				},
				{
					Secret: "aws/*",
					AllowedBinaries: []string{
						"/usr/bin/aws-cli",
					},
				},
			},
		},
	}

	// 1. Access Control Disabled
	t.Run("Disabled", func(t *testing.T) {
		ls := &Locksmith{Config: &Config{AccessControl: AccessControlConfig{Enabled: false}}}
		err := ls.VerifyAccess("db/password")
		if err != nil {
			t.Errorf("expected no error when disabled, got %v", err)
		}
	})

	// 2. Allowed Binary Match
	t.Run("AllowedBinary", func(t *testing.T) {
		ls := &Locksmith{Config: cfg}
		getCallingBinary = func() (string, error) {
			return "/usr/bin/postgres", nil
		}

		err := ls.VerifyAccess("db/password")
		if err != nil {
			t.Errorf("expected access allowed, got %v", err)
		}
	})

	// 3. Blocked Binary Match
	t.Run("BlockedBinary", func(t *testing.T) {
		ls := &Locksmith{Config: cfg}
		getCallingBinary = func() (string, error) {
			return "/usr/bin/curl", nil
		}

		err := ls.VerifyAccess("db/password")
		if !errors.Is(err, ErrAccessDenied) {
			t.Errorf("expected ErrAccessDenied, got %v", err)
		}
	})

	// 4. Glob Matching - Allowed
	t.Run("GlobMatchingAllowed", func(t *testing.T) {
		ls := &Locksmith{Config: cfg}
		getCallingBinary = func() (string, error) {
			return "/usr/bin/aws-cli", nil
		}

		err := ls.VerifyAccess("aws/secret-token")
		if err != nil {
			t.Errorf("expected access allowed via glob, got %v", err)
		}
	})

	// 5. Glob Matching - Blocked
	t.Run("GlobMatchingBlocked", func(t *testing.T) {
		ls := &Locksmith{Config: cfg}
		getCallingBinary = func() (string, error) {
			return "/usr/bin/postgres", nil
		}

		err := ls.VerifyAccess("aws/secret-token")
		if !errors.Is(err, ErrAccessDenied) {
			t.Errorf("expected ErrAccessDenied via glob, got %v", err)
		}
	})

	// 6. Open-By-Default (No matching rules)
	t.Run("OpenByDefault", func(t *testing.T) {
		ls := &Locksmith{Config: cfg}
		getCallingBinary = func() (string, error) {
			return "/usr/bin/curl", nil
		}

		err := ls.VerifyAccess("other/general-secret")
		if err != nil {
			t.Errorf("expected open-by-default access allowed, got %v", err)
		}
	})
}
