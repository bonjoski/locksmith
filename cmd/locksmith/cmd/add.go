package cmd

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/spf13/cobra"
)

var secretType string
var ownerApplication string
var sourceURL string

const defaultAddTTL = 30 * 24 * time.Hour

var addCmd = &cobra.Command{
	Use:     "add <key> <secret>",
	Short:   "Store a secret",
	Long:    "Store a secret.\n\nIf key/secret args are omitted, locksmith prompts interactively. During interactive add,\noptional rotation metadata is also prompted:\n- secret type: password | api_key | oauth_token | token\n- owner app: provider/application identifier (for example: github, gitlab)\n- source URL: rotation endpoint URL\n\nAll metadata fields are optional and may be left blank.",
	Example: "  locksmith add my/key my-secret\n  locksmith add my/key my-secret --type oauth_token --owner-app github --source-url https://api.github.com\n  locksmith add",
	Args:    cobra.MaximumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := ""
		secret := ""
		promptMode := false

		if len(args) > 0 {
			key = args[0]
		}
		if len(args) > 1 {
			secret = args[1]
		}

		reader := bufio.NewReader(cmd.InOrStdin())
		if key == "" {
			promptMode = true
			_, _ = fmt.Fprint(cmd.OutOrStdout(), "Key: ")
			input, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("error reading key: %w", err)
			}
			key = strings.TrimSpace(input)
		}

		if secret == "" {
			promptMode = true
			_, _ = fmt.Fprint(cmd.OutOrStdout(), "Secret: ")
			input, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("error reading secret: %w", err)
			}
			secret = strings.TrimRight(input, "\r\n")
		}

		if promptMode {
			if secretType == "" {
				_, _ = fmt.Fprint(cmd.OutOrStdout(), "Secret type (optional: password|api_key|oauth_token|token): ")
				input, err := reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("error reading secret type: %w", err)
				}
				secretType = strings.TrimSpace(input)
			}

			if ownerApplication == "" {
				_, _ = fmt.Fprint(cmd.OutOrStdout(), "Owner app (optional, example: github): ")
				input, err := reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("error reading owner app: %w", err)
				}
				ownerApplication = strings.TrimSpace(input)
			}

			if sourceURL == "" {
				_, _ = fmt.Fprint(cmd.OutOrStdout(), "Source URL (optional): ")
				input, err := reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("error reading source URL: %w", err)
				}
				sourceURL = strings.TrimSpace(input)
			}
		}

		secretBytes := []byte(secret)

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
	addCmd.Flags().StringVar(&secretType, "type", "", "Optional secret type for rotator selection: password|api_key|oauth_token|token")
	addCmd.Flags().StringVar(&ownerApplication, "owner-app", "", "Optional owner application/provider identifier (for example: github, gitlab)")
	addCmd.Flags().StringVar(&sourceURL, "source-url", "", "Optional source endpoint URL used by rotator selection")
}
