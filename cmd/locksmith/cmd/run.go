package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var envFile string
var exitFunc = os.Exit

var runCmd = &cobra.Command{
	Use:   "run [--env-file <path>] [--] <command> [args...]",
	Short: "Execute a command with secrets injected into its environment",
	Long: `Execute a command with secrets injected into its environment.
Secrets can be specified in the environment or an env file.

Supported formats:
  - Environment variables prefixed with LOCKSMITH_SECRET_:
    e.g. LOCKSMITH_SECRET_DB_PASSWORD=db/password resolves to DB_PASSWORD=<value>
  - Environment variables whose value starts with locksmith://:
    e.g. DATABASE_URL=locksmith://db/password resolves to DATABASE_URL=<value>`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Run command using global locksmith instance (ls)
		exitCode, err := ls.Run(args, envFile)
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
}
