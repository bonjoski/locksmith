package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/pkg/locksmith"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Handle global flags
	if os.Args[1] == "--version" || os.Args[1] == "-v" {
		fmt.Printf("locksmith v%s\n", locksmith.Version)
		return
	}

	if os.Args[1] == "help" || os.Args[1] == "-h" || os.Args[1] == "--help" {
		printUsage()
		return
	}

	ls, err := locksmith.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing locksmith: %v\n", err)
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	var cmdErr error
	switch command {
	case "add":
		cmdErr = handleAdd(ls, args)
	case "get":
		cmdErr = handleGet(ls, args)
	case "list":
		cmdErr = handleList(ls, args)
	case "delete":
		cmdErr = handleDelete(ls, args)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}

	if cmdErr != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", cmdErr)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: locksmith <command> [arguments]")
	fmt.Println("\nCommands:")
	fmt.Println("  add <key> <secret> [--expires <duration>]  Store a secret (default expires in 30d)")
	fmt.Println("  get <key>                                  Retrieve a secret (requires biometrics)")
	fmt.Println("  list                                       List all stored keys and metadata")
	fmt.Println("  delete <key>                               Remove a secret")
}

func handleAdd(ls *locksmith.Locksmith, args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	expiresStr := fs.String("expires", "30d", "Expiration duration (e.g. 1h, 30d, 1w)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	cmdArgs := fs.Args()
	if len(cmdArgs) < 2 {
		return fmt.Errorf("usage: locksmith add <key> <secret> [--expires <duration>]")
	}

	key := cmdArgs[0]
	secretStr := cmdArgs[1]
	// Convert string to []byte
	secretBytes := []byte(secretStr)
	defer func() {
		// Zero out the secret after use
		for i := range secretBytes {
			secretBytes[i] = 0
		}
	}()

	duration, err := ParseDuration(*expiresStr)
	if err != nil {
		return fmt.Errorf("invalid expiration duration: %w", err)
	}

	expiresAt := time.Now().Add(duration)
	err = ls.Set(key, secretBytes, expiresAt)
	if err != nil {
		return fmt.Errorf("error saving secret: %w", err)
	}

	fmt.Printf("Successfully saved secret '%s' (expires at %v)\n", key, expiresAt.Format(time.RFC822))
	return nil
}

func handleGet(ls *locksmith.Locksmith, args []string) error {
	// Parse flags
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fs.SetOutput(os.Stderr) // Send flag errors to stderr
	jsonOutput := fs.Bool("json", false, "Output in JSON format")

	if err := fs.Parse(args); err != nil {
		return err
	}

	cmdArgs := fs.Args()
	if len(cmdArgs) < 1 {
		return fmt.Errorf("usage: locksmith get <key> [--json]")
	}

	key := cmdArgs[0]

	// Load config
	config, err := locksmith.LoadConfig()
	if err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}

	// Get secret with metadata
	secret, err := ls.GetWithMetadata(key)
	if err != nil {
		return fmt.Errorf("error retrieving secret: %w", err)
	}

	defer secret.Zero()

	// JSON output
	if *jsonOutput {
		return outputJSON(key, secret, config)
	}

	// Show expiration warning (to stderr)
	if config.Notifications.ShowOnGet {
		notifier := locksmith.NewNotifier(config)
		notifier.NotifyExpiration(key, secret)
	}

	// Output secret value (to stdout)
	fmt.Println(string(secret.Value))
	return nil
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

func handleList(ls *locksmith.Locksmith, _ []string) error {
	items, err := ls.ListWithMetadata()
	if err != nil {
		return fmt.Errorf("error listing secrets: %w", err)
	}

	if len(items) == 0 {
		fmt.Println("No secrets stored.")
		return nil
	}

	// Load config
	config, err := locksmith.LoadConfig()
	if err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}

	threshold, _ := config.GetExpiringThreshold()

	// Print header
	fmt.Printf("%-30s %-20s %-20s %-12s\n", "KEY", "CREATED", "EXPIRES", "STATUS")
	fmt.Println(strings.Repeat("-", 84))

	// Print each secret
	for key, metadata := range items {
		// Skip if metadata is empty (not in cache)
		if metadata.ExpiresAt.IsZero() {
			fmt.Printf("%-30s %-20s %-20s %-12s\n",
				truncate(key, 30), "N/A", "N/A", "Unknown")
			continue
		}

		status := getStatusDisplay(metadata, threshold, config.Notifications.ShowOnList)
		expiresStr := metadata.ExpiresAt.Format("2006-01-02")
		createdStr := metadata.CreatedAt.Format("2006-01-02")

		fmt.Printf("%-30s %-20s %-20s %s\n",
			truncate(key, 30), createdStr, expiresStr, status)
	}

	return nil
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

func handleDelete(ls *locksmith.Locksmith, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: locksmith delete <key>")
	}

	key := args[0]
	err := ls.Delete(key)
	if err != nil {
		return fmt.Errorf("error deleting secret: %w", err)
	}

	fmt.Printf("Successfully deleted secret '%s'\n", key)
	return nil
}

func ParseDuration(s string) (time.Duration, error) {
	s = strings.ToLower(s)
	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		var days int
		_, err := fmt.Sscanf(daysStr, "%d", &days)
		if err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	if strings.HasSuffix(s, "w") {
		weeksStr := strings.TrimSuffix(s, "w")
		var weeks int
		_, err := fmt.Sscanf(weeksStr, "%d", &weeks)
		if err != nil {
			return 0, err
		}
		return time.Duration(weeks) * 7 * 24 * time.Hour, nil
	}
	if strings.HasSuffix(s, "mo") {
		// Simplified month as 30 days
		monthsStr := strings.TrimSuffix(s, "mo")
		var months int
		_, err := fmt.Sscanf(monthsStr, "%d", &months)
		if err != nil {
			return 0, err
		}
		return time.Duration(months) * 30 * 24 * time.Hour, nil
	}
	if strings.HasSuffix(s, "y") {
		// Simplified year as 365 days
		yearsStr := strings.TrimSuffix(s, "y")
		var years int
		_, err := fmt.Sscanf(yearsStr, "%d", &years)
		if err != nil {
			return 0, err
		}
		return time.Duration(years) * 365 * 24 * time.Hour, nil
	}

	return time.ParseDuration(s)
}
