//go:build !windows

package locksmith

import (
	"os"
	"testing"
)

func TestCheckBinaryAccess_NoDenyOrAllow(t *testing.T) {
	// With empty deny and allow lists, any binary should be allowed.
	l := &Locksmith{Options: Options{}}
	if err := l.checkBinaryAccess(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCheckBinaryAccess_DenyList(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get executable path: %v", err)
	}
	l := &Locksmith{Options: Options{DenyBinaries: []string{exe}}}
	if err := l.checkBinaryAccess(); err == nil {
		t.Fatalf("expected error due to deny list, got nil")
	}
}

func TestCheckBinaryAccess_AllowList(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get executable path: %v", err)
	}
	// Allow list contains the current binary; should succeed.
	l := &Locksmith{Options: Options{AllowBinaries: []string{exe}}}
	if err := l.checkBinaryAccess(); err != nil {
		t.Fatalf("expected no error with allow list, got %v", err)
	}
}
