package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var envFile string
var sliceKey string
var exitFunc = os.Exit

var runCmd = &cobra.Command{
	Use:   "run [--env-file <path>] [--slice [secret-key]] [--] <command> [args...]",
	Short: "Execute a command with secrets injected into its environment or memory slice",
	Long: `Execute a command with secrets injected into its environment or inherited memory slice.
Secrets can be specified in the environment or an env file.

Memory Slicing (--slice):
  Injects credentials via an anonymous inherited file descriptor (FD 3) instead of
  setting plaintext environment variables, eliminating memory scraping and /proc/<pid>/environ exposure.

  e.g.:
    locksmith run --slice my-secret-key -- python3 -c "import os; print(os.fdopen(int(os.environ['LOCKSMITH_FD'])).read())"
    locksmith run --slice --env-file .env -- my-agent`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		defer func() {
			envFile = ""
			sliceKey = ""
			_ = cmd.Flags().Set("env-file", "")
			_ = cmd.Flags().Set("slice", "")
		}()

		var exitCode int
		var err error

		if sliceKey != "" {
			dashIdx := cmd.ArgsLenAtDash()
			var effectiveSliceKey string
			var commandArgs []string

			if sliceKey == "true" {
				if dashIdx > 0 {
					effectiveSliceKey = args[0]
					commandArgs = args[dashIdx:]
				} else {
					effectiveSliceKey = ""
					commandArgs = args
				}
			} else {
				effectiveSliceKey = sliceKey
				if dashIdx > 0 {
					commandArgs = args[dashIdx:]
				} else {
					commandArgs = args
				}
			}

			if len(commandArgs) == 0 {
				return cmd.Help()
			}

			exitCode, err = ls.RunSlice(commandArgs, effectiveSliceKey, envFile)
		} else {
			exitCode, err = ls.Run(args, envFile)
		}

		if err != nil {
			return err
		}

		// Exit with the child process exit code
		exitFunc(exitCode)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVarP(&envFile, "env-file", "f", "", "Path to an environment file")
	runCmd.Flags().StringVar(&sliceKey, "slice", "", "Pass secrets via inherited file descriptor (FD 3) instead of plaintext environment variables")
	runCmd.Flags().Lookup("slice").NoOptDefVal = "true"
}
