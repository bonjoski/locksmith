package cmd

import (
	"fmt"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/spf13/cobra"
)

var expiresStr string

var addCmd = &cobra.Command{
	Use:   "add <key> <secret>",
	Short: "Store a secret",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]
		secretStr := args[1]
		secretBytes := []byte(secretStr)
		defer func() {
			for i := range secretBytes {
				secretBytes[i] = 0
			}
		}()

		duration, err := locksmith.ParseDuration(expiresStr)
		if err != nil {
			return fmt.Errorf("invalid expiration duration: %w", err)
		}

		expiresAt := time.Now().Add(duration)
		if err := ls.Set(key, secretBytes, expiresAt); err != nil {
			return fmt.Errorf("error saving secret: %w", err)
		}

		fmt.Printf("Successfully saved secret '%s' (expires at %v)\n", key, expiresAt.Format(time.RFC822))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(addCmd)
	addCmd.Flags().StringVar(&expiresStr, "expires", "30d", "Expiration duration (e.g. 1h, 30d, 1w)")
}
