package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var rotateAll bool

var rotateCmd = &cobra.Command{
	Use:   "rotate [key]",
	Short: "Rotate secrets automatically using configured hooks",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 && !rotateAll {
			return fmt.Errorf("either specify a secret key to rotate or use the --all flag")
		}

		if len(args) > 0 {
			key := args[0]
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Forcing rotation of secret '%s'...\n", key)
			err := ls.RotateSecret(key)
			if err != nil {
				return fmt.Errorf("failed to rotate secret '%s': %w", key, err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Successfully rotated secret '%s'\n", key)
			return nil
		}

		// Rotate all expiring secrets
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Scanning for expiring credentials...")
		rotated, skipped, failed, err := ls.RotateExpiringSecrets()
		if err != nil {
			return fmt.Errorf("failed to scan and rotate secrets: %w", err)
		}

		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Rotation summary:")
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  - Rotated: %d secret(s)\n", len(rotated))
		for _, r := range rotated {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    * %s\n", r)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  - Skipped: %d secret(s)\n", len(skipped))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  - Failed:  %d secret(s)\n", len(failed))
		for k, e := range failed {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    * %s: %v\n", k, e)
		}

		if len(failed) > 0 {
			return fmt.Errorf("rotation completed with errors")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(rotateCmd)
	rotateCmd.Flags().BoolVarP(&rotateAll, "all", "a", false, "Rotate all expiring secrets")
}
