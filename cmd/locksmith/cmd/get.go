package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/spf13/cobra"
)

var (
	jsonOutput bool
	noNewline  bool
)

var getCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Retrieve a secret",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]

		secret, err := ls.GetWithMetadata(key)
		if err != nil {
			return fmt.Errorf("error retrieving secret: %w", err)
		}
		defer secret.Zero()

		if jsonOutput {
			return outputJSON(key, secret, cfg)
		}

		if cfg.Notifications.ShowOnGet {
			notifier := locksmith.NewNotifier(cfg)
			notifier.NotifyExpiration(key, secret)
		}

		if noNewline {
			fmt.Print(string(secret.Value))
		} else {
			fmt.Println(string(secret.Value))
		}

		return nil
	},
}

func outputJSON(key string, secret *locksmith.Secret, config *locksmith.Config) error {
	threshold, _ := config.GetExpiringThreshold()
	status := secret.GetExpirationStatus(threshold)

	output := map[string]interface{}{
		"key":         key,
		"value":       string(secret.Value),
		"created_at":  secret.CreatedAt,
		"expires_at":  secret.ExpiresAt,
		"expires_in":  secret.TimeUntilExpiration().String(),
		"is_expired":  secret.IsExpired(),
		"is_expiring": status == locksmith.StatusExpiring,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func init() {
	rootCmd.AddCommand(getCmd)
	getCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	getCmd.Flags().BoolVarP(&noNewline, "no-newline", "n", false, "Do not print a trailing newline")
}
