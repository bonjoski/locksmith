//go:build locksmith_test_harness

package cmd

import (
	"os"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

func initTestHarnessLocksmith(cfg *locksmith.Config) bool {
	if os.Getenv("LOCKSMITH_MOCK_BACKEND") == "1" || os.Getenv("LOCKSMITH_FORCE_SEAL_FAIL") == "1" {
		cache := locksmith.NewMockCache()
		ls = locksmith.NewWithCache(cache)
		mb := locksmith.NewMockBackend()
		if os.Getenv("LOCKSMITH_FORCE_SEAL_FAIL") == "1" {
			mb.ForceSealFail = true
		}
		ls.Backend = mb
		ls.Config = cfg
		ls.Options.RequireBiometrics = false
		return true
	}
	return false
}
