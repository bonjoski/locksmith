package cmd

import (
	"fmt"
	"os"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/spf13/cobra"
)

var (
	ls                  *locksmith.Locksmith
	cfg                 *locksmith.Config
	globalBiometricReqs bool
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
			opts := locksmith.Options{
				RequireBiometrics: true, // EXE always requires biometrics
				PromptMessage:     cfg.Auth.PromptMessage,
			}
			var err error
			ls, err = locksmith.NewWithOptions(opts)
			if err != nil {
				return fmt.Errorf("error initializing locksmith: %w", err)
			}
		} else {
			// Apply config to injected test double
			ls.Options.RequireBiometrics = globalBiometricReqs
			ls.Options.PromptMessage = cfg.Auth.PromptMessage
		}

		return nil
	},
}

func Execute(v string) {
	if v != "" {
		rootCmd.Version = v
	}
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
}
