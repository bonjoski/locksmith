package main

import (
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

	switch command {
	case "add":
		handleAdd(ls, args)
	case "get":
		handleGet(ls, args)
	case "list":
		handleList(ls, args)
	case "delete":
		handleDelete(ls, args)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
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

func handleAdd(ls *locksmith.Locksmith, args []string) {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	expiresStr := fs.String("expires", "30d", "Expiration duration (e.g. 1h, 30d, 1w)")

	// Parse subcommand flags from the provided args
	err := fs.Parse(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing arguments for add command: %v\n", err)
		os.Exit(1)
	}

	// Now, fs.Args() will contain the non-flag arguments for the 'add' command
	cmdArgs := fs.Args()

	if len(cmdArgs) < 2 {
		fmt.Println("Usage: locksmith add <key> <secret> [--expires <duration>]")
		os.Exit(1)
	}

	key := cmdArgs[0]
	secret := cmdArgs[1]

	duration, err := parseDuration(*expiresStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid expiration duration: %v\n", err)
		os.Exit(1)
	}

	expiresAt := time.Now().Add(duration)
	err = ls.Set(key, secret, expiresAt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error saving secret: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully saved secret '%s' (expires at %v)\n", key, expiresAt.Format(time.RFC822))
}

func handleGet(ls *locksmith.Locksmith, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: locksmith get <key>")
		os.Exit(1)
	}

	key := args[0]
	value, err := ls.Get(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving secret: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(value)
}

func handleList(ls *locksmith.Locksmith, _ []string) {
	items, err := ls.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing secrets: %v\n", err)
		os.Exit(1)
	}

	if len(items) == 0 {
		fmt.Println("No secrets stored.")
		return
	}

	fmt.Printf("%-20s %-20s %-20s\n", "KEY", "CREATED", "EXPIRES")
	fmt.Println(strings.Repeat("-", 62))
	for key := range items {
		// Note: Metadata is currently empty because native_list only returns keys.
		// Future enhancement: parse metadata during list.
		fmt.Printf("%-20s %-20s %-20s\n", key, "N/A", "N/A")
	}
}

func handleDelete(ls *locksmith.Locksmith, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: locksmith delete <key>")
		os.Exit(1)
	}

	key := args[0]
	err := ls.Delete(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deleting secret: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully deleted secret '%s'\n", key)
}

func parseDuration(s string) (time.Duration, error) {
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
	if strings.HasSuffix(s, "m") {
		// Simplified month as 30 days
		monthsStr := strings.TrimSuffix(s, "m")
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
