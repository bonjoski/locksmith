package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var expiresStr string

var addCmd = &cobra.Command{
	Use:   "add <key> [secret]",
	Short: "Store a secret",
	Args:  cobra.RangeArgs(0, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		var key string
		var secretBytes []byte
		var err error

		if len(args) > 0 {
			key = args[0]
		} else {
			_, _ = fmt.Fprint(cmd.OutOrStdout(), "Enter key name: ")
			_, err = fmt.Fscanln(cmd.InOrStdin(), &key)
			if err != nil {
				return fmt.Errorf("error reading key: %w", err)
			}
			if key == "" {
				return fmt.Errorf("key cannot be empty")
			}
		}

		if len(args) == 2 {
			secretBytes = []byte(args[1])
		} else {
			_, _ = fmt.Fprint(cmd.OutOrStdout(), "Enter secret: ")
			if f, ok := cmd.InOrStdin().(*os.File); ok && term.IsTerminal(int(f.Fd())) {
				secretBytes, err = term.ReadPassword(int(f.Fd()))
				_, _ = fmt.Fprintln(cmd.OutOrStdout())
			} else {
				// Fallback for non-terminal input (e.g. tests or piped input)
				var secretStr string
				_, err = fmt.Fscanln(cmd.InOrStdin(), &secretStr)
				secretBytes = []byte(secretStr)
			}
			if err != nil {
				return fmt.Errorf("error reading secret: %w", err)
			}
			if len(secretBytes) == 0 {
				return fmt.Errorf("secret cannot be empty")
			}
		}

		var moduleAccess bool
		_, _ = fmt.Fprint(cmd.OutOrStdout(), "Will this token be accessed via the module? (y/N): ")
		var resp string
		_, _ = fmt.Fscanln(cmd.InOrStdin(), &resp)
		if resp == "y" || resp == "Y" || resp == "yes" {
			moduleAccess = true
		}

		duration, err := locksmith.ParseDuration(expiresStr)
		if err != nil {
			return fmt.Errorf("invalid expiration duration: %w", err)
		}

		expiresAt := time.Now().Add(duration)
		// Use SetWithBiometrics to override the default requirement if it's for the module
		if err := ls.SetWithBiometrics(key, secretBytes, expiresAt, !moduleAccess); err != nil {
			return fmt.Errorf("error saving secret: %w", err)
		}

		// Zero the secret bytes after use
		for i := range secretBytes {
			secretBytes[i] = 0
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Successfully saved secret '%s' (expires at %v)\n", key, expiresAt.Format(time.RFC822))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(addCmd)
	addCmd.Flags().StringVar(&expiresStr, "expires", "30d", "Expiration duration (e.g. 1h, 30d, 1w)")
}
