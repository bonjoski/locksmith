//go:build !locksmith_test_harness

package cmd

import "github.com/bonjoski/locksmith/v2/pkg/locksmith"

func initTestHarnessLocksmith(_ *locksmith.Config) bool {
	return false
}
