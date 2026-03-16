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
	allowNoBiometrics   bool
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

		// Guard rail verification
		if !globalBiometricReqs && !allowNoBiometrics {
			return fmt.Errorf("config disables biometrics, but --allow-no-biometrics was not passed")
		}

		// Initialize Locksmith
		if ls == nil {
			opts := locksmith.Options{
				RequireBiometrics: globalBiometricReqs,
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

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&allowNoBiometrics, "allow-no-biometrics", false, "acknowledge the risk when config disables interactive biometric prompts")
}
