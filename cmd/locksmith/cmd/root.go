package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/bonjoski/locksmith/v2/pkg/ux"
	"github.com/spf13/cobra"
)

var (
	ls                  *locksmith.Locksmith
	cfg                 *locksmith.Config
	globalBiometricReqs bool
	nonInteractive      bool
	showWhy             bool
)

var rootCmd = &cobra.Command{
	Use:     "locksmith",
	Short:   "A hardware-bound biometric credential manager",
	Version: locksmith.Version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Initialize Config
		if cfg == nil {
			var err error
			cfg, err = locksmith.LoadConfig()
			if err != nil {
				return fmt.Errorf("error loading config: %w", err)
			}
		}

		globalBiometricReqs = cfg.Auth.RequireBiometrics

		// Initialize Locksmith
		if ls == nil {
			if initTestHarnessLocksmith(cfg) {
				return nil
			}
			opts := locksmith.Options{
				RequireBiometrics: !nonInteractive,
				OnlyCached:        nonInteractive,
				PromptMessage:     cfg.Auth.PromptMessage,
			}
			var err error
			ls, err = locksmith.NewWithOptions(opts)
			if err != nil {
				if nonInteractive {
					fmt.Fprintln(os.Stderr, "ERR_BIOMETRIC_INTERACTION_REQUIRED: interactive biometric prompt blocked in non-interactive mode. Use 'locksmith session' or acquire an ambient lease.")
					os.Exit(82)
				}
				return fmt.Errorf("error initializing locksmith: %w", err)
			}
			ls.Config = cfg
		} else {
			// Apply config to injected test double
			ls.Options.RequireBiometrics = globalBiometricReqs && !nonInteractive
			ls.Options.OnlyCached = nonInteractive
			ls.Options.PromptMessage = cfg.Auth.PromptMessage
			ls.Config = cfg
		}

		return nil
	},
}

func Execute(v string) {
	if v != "" {
		rootCmd.Version = v
	}
	// If run as git-credential-locksmith, insert "credential" subcommand argument
	if filepath.Base(os.Args[0]) == "git-credential-locksmith" {
		if len(os.Args) < 2 || os.Args[1] != "credential" {
			newArgs := make([]string, 0, len(os.Args)+1)
			newArgs = append(newArgs, os.Args[0], "credential")
			newArgs = append(newArgs, os.Args[1:]...)
			os.Args = newArgs
		}
	}
	if err := rootCmd.Execute(); err != nil {
		var ffe *ux.FixForwardError
		if errors.As(err, &ffe) {
			code := ffe.ExitCode
			if code == 0 {
				code = 1
			}
			os.Exit(code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&nonInteractive, "non-interactive", false, "Prevent interactive prompts; exit 82 if authentication required")
	rootCmd.PersistentFlags().BoolVar(&showWhy, "why", false, "Show progressive disclosure explanation, threat model, and references")

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number of locksmith",
		Run: func(cmd *cobra.Command, args []string) {
			v := rootCmd.Version
			if v == "" {
				v = locksmith.Version
			}
			fmt.Printf("locksmith version %s\n", v)
		},
	})
}
