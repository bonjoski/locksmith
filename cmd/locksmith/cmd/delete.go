package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var deleteCmd = &cobra.Command{
	Use:   "delete <key>",
	Short: "Remove a secret",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]
		if err := ls.Delete(key); err != nil {
			return fmt.Errorf("error deleting secret: %w", err)
		}

		fmt.Printf("Successfully deleted secret '%s'\n", key)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(deleteCmd)
}
