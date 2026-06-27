package native

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetCallingProcessInfo(t *testing.T) {
	info, err := GetCallingProcessInfo()
	if err != nil {
		t.Fatalf("GetCallingProcessInfo failed: %v", err)
	}

	if info == nil {
		t.Fatal("Expected non-nil ProcessInfo")
	}

	if info.Path == "" {
		t.Error("Expected non-empty process path")
	}

	// The path should be an absolute path
	if !filepath.IsAbs(info.Path) {
		t.Errorf("Expected absolute path, got: %s", info.Path)
	}

	// Verify that the executable exists
	if _, err := os.Stat(info.Path); err != nil {
		t.Errorf("Process path does not exist on disk: %v", err)
	}

	// If we are running on macOS, we can check codesign info, though test runners
	// might be ad-hoc signed or unsigned. So we just check that it parses without panic.
	t.Logf("Calling process path: %s", info.Path)
	t.Logf("Calling process identifier: %s", info.Identifier)
	t.Logf("Calling process team ID: %s", info.TeamID)
}

func TestShellBinariesCheck(t *testing.T) {
	// Verify that some common shells are correctly identified
	shells := []string{"sh", "bash", "zsh", "fish"}
	for _, s := range shells {
		if !shellBinaries[s] {
			t.Errorf("Expected %s to be recognized as a shell binary", s)
		}
	}

	// Verify non-shells are not skipped
	nonShells := []string{"aws", "git", "locksmith", "python"}
	for _, ns := range nonShells {
		if shellBinaries[ns] {
			t.Errorf("Expected %s NOT to be recognized as a shell binary", ns)
		}
	}
}
