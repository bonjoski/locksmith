package cmd

import (
	"github.com/spf13/cobra"
)

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Token management commands",
}

var tokenGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Retrieve a secret (alias for get)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Just call the main get command's RunE
		return getCmd.RunE(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(tokenCmd)
	tokenCmd.AddCommand(tokenGetCmd)

	// Add the same flags to token get as the main get command
	tokenGetCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	tokenGetCmd.Flags().BoolVarP(&noNewline, "no-newline", "n", false, "Do not print a trailing newline")
}
