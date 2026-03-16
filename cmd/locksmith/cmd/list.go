package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all stored keys and metadata",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		items, err := ls.ListWithMetadata()
		if err != nil {
			return fmt.Errorf("error listing secrets: %w", err)
		}

		if len(items) == 0 {
			fmt.Println("No secrets stored.")
			return nil
		}

		threshold, _ := cfg.GetExpiringThreshold()

		fmt.Printf("%-30s %-20s %-20s %-12s\n", "KEY", "CREATED", "EXPIRES", "STATUS")
		fmt.Println(strings.Repeat("-", 84))

		for key, metadata := range items {
			if metadata.ExpiresAt.IsZero() {
				fmt.Printf("%-30s %-20s %-20s %-12s\n",
					truncate(key, 30), "N/A", "N/A", "Unknown")
				continue
			}

			status := getStatusDisplay(metadata, threshold, cfg.Notifications.ShowOnList)
			expiresStr := metadata.ExpiresAt.Format("2006-01-02")
			createdStr := metadata.CreatedAt.Format("2006-01-02")

			fmt.Printf("%-30s %-20s %-20s %s\n",
				truncate(key, 30), createdStr, expiresStr, status)
		}

		return nil
	},
}

func getStatusDisplay(metadata *locksmith.SecretMetadata, threshold time.Duration, showStatus bool) string {
	if !showStatus {
		return ""
	}

	status := metadata.GetExpirationStatus(threshold)

	switch status {
	case locksmith.StatusExpired:
		return "❌ Expired"
	case locksmith.StatusExpiring:
		return "⚠️  Expiring"
	default:
		return "✓  Valid"
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func init() {
	rootCmd.AddCommand(listCmd)
}
