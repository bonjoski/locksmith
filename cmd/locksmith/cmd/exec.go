package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var execCmd = &cobra.Command{
	Use:   "exec <integration> [--] [args...]",
	Short: "Run a configured integration command with Locksmith-backed environment variables",
	Long: `Run a configured integration command with Locksmith-backed environment variables.

Built-in integrations:
  - gh   (injects GH_TOKEN from locksmith://github/gh/token)
  - glab (injects GITLAB_TOKEN from locksmith://gitlab/glab/token)

You can override or define integration profiles in ~/.locksmith/config.yml under "integrations".`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		integrationName := args[0]
		childArgs := []string{}
		if len(args) > 1 {
			childArgs = args[1:]
		}

		exitCode, err := ls.RunIntegration(integrationName, childArgs)
		if err != nil {
			return fmt.Errorf("failed to execute integration '%s': %w", integrationName, err)
		}

		exitFunc(exitCode)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(execCmd)
}
