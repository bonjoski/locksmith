//go:build test_native && locksmith_admin

package native

import "testing"

func TestNativeWrapperCoverage(t *testing.T) {
	// Prepare secret and ensure it's zeroed after test
	secret := []byte("secret")
	defer func() { for i := range secret { secret[i] = 0 } }()
	// Call each wrapper function to exercise its code paths.
	// Errors are expected on a fresh system, but we ignore them.
	_ = Set("testsvc", "testacc", secret, false)
	got, _ := Get("testsvc", "testacc", false, "prompt")
	defer func() { for i := range got { got[i] = 0 } }()
	_ = Delete("testsvc", "testacc", false, "prompt")
	_, _ = List("testsvc", false, "prompt")
}
