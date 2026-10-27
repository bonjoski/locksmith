package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	cockpitDetach bool
)

var cockpitCmd = &cobra.Command{
	Use:   "cockpit",
	Short: "Launch the Locksmith Cockpit desktop application",
	Long: `Launches the Locksmith Cockpit biometric credential control plane.
Looks for locksmith-cockpit on PATH, standard application directories,
or adjacent to the locksmith binary.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cockpitPath, err := findCockpitBinary()
		if err != nil {
			return err
		}

		c := exec.Command(cockpitPath, args...)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		c.Stdin = os.Stdin

		if cockpitDetach {
			if err := c.Start(); err != nil {
				return fmt.Errorf("failed to start locksmith-cockpit: %w", err)
			}
			fmt.Printf("Started Locksmith Cockpit (PID %d)\n", c.Process.Pid)
			return nil
		}

		return c.Run()
	},
}

func findCockpitBinary() (string, error) {
	binName := "locksmith-cockpit"
	if runtime.GOOS == "windows" {
		binName = "locksmith-cockpit.exe"
	}

	// 1. Check PATH
	if p, err := exec.LookPath(binName); err == nil {
		return p, nil
	}
	if p, err := exec.LookPath("locksmith-cockpit"); err == nil {
		return p, nil
	}

	// 2. Check adjacent to current executable
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for _, name := range []string{binName, "locksmith-cockpit"} {
			candidate := filepath.Join(dir, name)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, nil
			}
		}
	}

	// 3. Check macOS .app bundle executable if on darwin
	if runtime.GOOS == "darwin" {
		home := os.Getenv("HOME")
		candidates := []string{
			"/Applications/Locksmith Cockpit.app/Contents/MacOS/locksmith-desktop",
			"/Applications/Locksmith Cockpit.app/Contents/MacOS/locksmith-cockpit",
			"/Applications/LocksmithCockpit.app/Contents/MacOS/locksmith-cockpit",
			filepath.Join(home, "Applications/Locksmith Cockpit.app/Contents/MacOS/locksmith-desktop"),
			filepath.Join(home, "Applications/Locksmith Cockpit.app/Contents/MacOS/locksmith-cockpit"),
			filepath.Join(home, "Applications/LocksmithCockpit.app/Contents/MacOS/locksmith-cockpit"),
		}
		for _, c := range candidates {
			if info, err := os.Stat(c); err == nil && !info.IsDir() {
				return c, nil
			}
		}
	}

	// 4. Check local development paths
	devCandidates := []string{
		"desktop/src-tauri/target/release/locksmith-desktop",
		"bin/locksmith-cockpit-darwin-arm64",
		"bin/locksmith-cockpit-darwin-amd64",
	}
	for _, c := range devCandidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c, nil
		}
	}

	return "", fmt.Errorf("locksmith-cockpit not found on PATH or in /Applications.\nInstall via 'brew install locksmith' or run 'make cockpit' in the development repository")
}

func init() {
	cockpitCmd.Flags().BoolVarP(&cockpitDetach, "detach", "d", false, "Run Locksmith Cockpit detached in the background")
	rootCmd.AddCommand(cockpitCmd)
}
