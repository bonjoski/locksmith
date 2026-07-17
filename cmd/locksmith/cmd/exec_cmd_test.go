package cmd

import "testing"

func TestExecCommandArgs(t *testing.T) {
	_, _ = setupTest()

	rootCmd.SetArgs([]string{"exec"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when running exec without integration name")
	}
}

func TestExecCommandUnknownIntegration(t *testing.T) {
	_, _ = setupTest()

	rootCmd.SetArgs([]string{"exec", "unknown-integration"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected unknown integration execution to fail")
	}
}
