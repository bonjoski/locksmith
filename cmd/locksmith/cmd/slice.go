package cmd

import (
	"github.com/spf13/cobra"
)

var sliceCmdEnvFile string

var sliceCmd = &cobra.Command{
	Use:   "slice [secret-key] [--] <command> [args...]",
	Short: "Execute a command with secrets injected via an inherited memory slice (FD 3)",
	Long: `Execute a command with secrets injected via an anonymous inherited file descriptor (FD 3)
residing exclusively in memory, leaving zero plaintext footprint in process environment tables.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		defer func() {
			sliceCmdEnvFile = ""
			_ = cmd.Flags().Set("env-file", "")
		}()

		dashIdx := cmd.ArgsLenAtDash()
		var effectiveSliceKey string
		var commandArgs []string

		if dashIdx > 0 {
			effectiveSliceKey = args[0]
			commandArgs = args[dashIdx:]
		} else if dashIdx == 0 {
			effectiveSliceKey = ""
			commandArgs = args
		} else {
			if len(args) > 1 {
				effectiveSliceKey = args[0]
				commandArgs = args[1:]
			} else {
				effectiveSliceKey = ""
				commandArgs = args
			}
		}

		if len(commandArgs) == 0 {
			return cmd.Help()
		}

		exitCode, err := ls.RunSlice(commandArgs, effectiveSliceKey, sliceCmdEnvFile)
		if err != nil {
			return err
		}

		exitFunc(exitCode)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(sliceCmd)
	sliceCmd.Flags().StringVarP(&sliceCmdEnvFile, "env-file", "f", "", "Path to an environment file")
}
