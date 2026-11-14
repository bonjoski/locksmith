package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestGitSignCLI(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)

	// Invoke git-sign help/description
	rootCmd.SetArgs([]string{"git-sign", "--help"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("git-sign --help failed: %v", err)
	}

	if !strings.Contains(buf.String(), "gpg.program") {
		t.Errorf("expected gpg.program in git-sign help output: %s", buf.String())
	}
}
