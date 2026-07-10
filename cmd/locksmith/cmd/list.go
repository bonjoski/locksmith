package cmd

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/spf13/cobra"
)

var listDetails bool

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored keys (or full metadata with --details)",
	Long:  "List stored secrets. By default this shows a concise table. Use --details to show full metadata for each secret, including secret type, owner app, source URL, and metadata map. Detailed metadata is returned from listing/cache paths and does not perform per-key secret reads.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		items, err := ls.ListWithMetadata()
		if err != nil {
			return fmt.Errorf("error listing secrets: %w", err)
		}

		if len(items) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No secrets stored.")
			return nil
		}

		threshold, _ := cfg.GetExpiringThreshold()
		keys := make([]string, 0, len(items))
		for key := range items {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		if listDetails {
			for i, key := range keys {
				metadata := items[key]
				if i > 0 {
					_, _ = fmt.Fprintln(cmd.OutOrStdout())
				}

				status := "unknown"
				if !metadata.ExpiresAt.IsZero() {
					switch metadata.GetExpirationStatus(threshold) {
					case locksmith.StatusExpired:
						status = "expired"
					case locksmith.StatusExpiring:
						status = "expiring"
					default:
						status = "valid"
					}
				}

				secretTypeVal := string(metadata.SecretType)
				if secretTypeVal == "" {
					secretTypeVal = "N/A"
				}

				ownerAppVal := metadata.OwnerApplication
				if ownerAppVal == "" {
					ownerAppVal = "N/A"
				}

				sourceURLVal := metadata.SourceURL
				if sourceURLVal == "" {
					sourceURLVal = "N/A"
				}

				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Key:        %s\n", key)
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Status:     %s\n", status)
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Created:    %s\n", formatDateTime(metadata.CreatedAt))
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Expires:    %s\n", formatDateTime(metadata.ExpiresAt))
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Type:       %s\n", secretTypeVal)
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Owner App:  %s\n", ownerAppVal)
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Source URL: %s\n", sourceURLVal)
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Metadata:")

				if len(metadata.Metadata) == 0 {
					_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  (none)")
					continue
				}

				metaKeys := make([]string, 0, len(metadata.Metadata))
				for mk := range metadata.Metadata {
					metaKeys = append(metaKeys, mk)
				}
				sort.Strings(metaKeys)
				for _, mk := range metaKeys {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: %s\n", mk, formatMetadataValue(mk, metadata.Metadata[mk]))
				}
			}
			return nil
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-30s %-20s %-20s %-12s\n", "KEY", "CREATED", "EXPIRES", "STATUS")
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("-", 84))

		for _, key := range keys {
			metadata := items[key]
			if metadata.ExpiresAt.IsZero() {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-30s %-20s %-20s %-12s\n",
					truncate(key, 30), "N/A", "N/A", "Unknown")
				continue
			}

			status := getStatusDisplay(metadata, threshold, cfg.Notifications.ShowOnList)
			expiresStr := metadata.ExpiresAt.Format("2006-01-02")
			createdStr := metadata.CreatedAt.Format("2006-01-02")

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-30s %-20s %-20s %s\n",
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

func formatDateTime(t time.Time) string {
	if t.IsZero() {
		return "N/A"
	}
	return t.Format(time.RFC3339)
}

func formatMetadataValue(key string, value string) string {
	if isSensitiveMetadataKey(key) {
		return "[REDACTED]"
	}

	sanitized := strings.ReplaceAll(value, "\n", "\\n")
	sanitized = strings.ReplaceAll(sanitized, "\r", "\\r")

	const maxLen = 120
	if len(sanitized) > maxLen {
		return sanitized[:maxLen] + "..."
	}

	if sanitized == "" {
		return "(empty)"
	}

	return sanitized
}

func isSensitiveMetadataKey(key string) bool {
	lowerKey := strings.ToLower(strings.TrimSpace(key))
	sensitiveFragments := []string{"secret", "private", "token", "password", "passwd", "key", "pem", "credential"}

	for _, fragment := range sensitiveFragments {
		if strings.Contains(lowerKey, fragment) {
			return true
		}
	}

	return false
}

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().BoolVar(&listDetails, "details", false, "Show full metadata for each secret in detailed view")
}
