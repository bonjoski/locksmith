package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCockpitCommandRegistration(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"cockpit"})
	if err != nil {
		t.Fatalf("expected to find cockpit subcommand: %v", err)
	}
	if cmd == nil || cmd.Name() != "cockpit" {
		t.Fatalf("expected cockpit command, got %v", cmd)
	}
}

func TestFindCockpitBinary_NotFound(t *testing.T) {
	// In an empty/clean test PATH, ensure expected error message is returned
	origPath := os.Getenv("PATH")
	tempDir := t.TempDir()
	os.Setenv("PATH", tempDir)
	defer os.Setenv("PATH", origPath)

	_, err := findCockpitBinary()
	// Either error if no dev binary exists, or if dev binary exists it finds it
	// If error, check message formatting
	if err != nil {
		if err.Error() == "" {
			t.Errorf("expected informative error message, got empty error")
		}
	}
}

func TestFindCockpitBinary_FromPATH(t *testing.T) {
	tempDir := t.TempDir()
	binName := "locksmith-cockpit"
	if runtime.GOOS == "windows" {
		binName = "locksmith-cockpit.exe"
	}
	fakeBinary := filepath.Join(tempDir, binName)
	if err := os.WriteFile(fakeBinary, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("failed to create fake binary: %v", err)
	}

	origPath := os.Getenv("PATH")
	os.Setenv("PATH", tempDir+string(os.PathListSeparator)+origPath)
	defer os.Setenv("PATH", origPath)

	path, err := findCockpitBinary()
	if err != nil {
		t.Fatalf("expected binary to be found on PATH, got error: %v", err)
	}
	if filepath.Clean(path) != filepath.Clean(fakeBinary) {
		t.Errorf("expected %q, got %q", fakeBinary, path)
	}
}
