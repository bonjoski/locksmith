package cmd

import (
	"fmt"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/spf13/cobra"
)

var secretType string
var ownerApplication string
var sourceURL string

const defaultAddTTL = 30 * 24 * time.Hour

var addCmd = &cobra.Command{
	Use:   "add <key> <secret>",
	Short: "Store a secret",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]
		secretBytes := []byte(args[1])

		if key == "" {
			return fmt.Errorf("key cannot be empty")
		}
		if len(secretBytes) == 0 {
			return fmt.Errorf("secret cannot be empty")
		}

		expiresAt := time.Now().Add(defaultAddTTL)
		typedSecretType := locksmith.ParseSecretType(secretType)
		// Use SetWithContext to persist secret metadata used for rotator auto-loading.
		if err := ls.SetWithContext(
			key,
			secretBytes,
			expiresAt,
			globalBiometricReqs,
			typedSecretType,
			ownerApplication,
			sourceURL,
			nil,
		); err != nil {
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
	addCmd.Flags().StringVar(&secretType, "type", "", "Secret type used for rotator auto-selection")
	addCmd.Flags().StringVar(&ownerApplication, "owner-app", "", "Owning application used for rotator auto-selection")
	addCmd.Flags().StringVar(&sourceURL, "source-url", "", "Source URL used for rotator auto-selection")
}
