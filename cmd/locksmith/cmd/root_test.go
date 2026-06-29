//go:build test_native && locksmith_admin

package cmd

import (
	"testing"
)

func TestRootExecute(t *testing.T) {
	// Setup a dummy Locksmith and Config to avoid real initialization which requires native keychain.
	// Disable the PersistentPreRunE to avoid real initialization.
	rootCmd.PersistentPreRunE = nil
	// Ensure no arguments are passed.
	rootCmd.SetArgs([]string{})
	Execute("test-version")
}
