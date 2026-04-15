package main

import (
	"fmt"
	"os"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

var version string

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		v := version
		if v == "" {
			v = locksmith.Version
		}
		fmt.Printf("summon-locksmith version %s\n", v)
		os.Exit(0)
	}

	// Summon provider contract: take secret ID as first argument
	// Force silent mode for Summon provider (no expiration warnings)
	_ = os.Setenv("LOCKSMITH_SILENT", "true")

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: summon-locksmith <secret-id>")
		os.Exit(1)
	}

	secretID := os.Args[1]

	// Initialize locksmith
	ls, err := locksmith.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing locksmith: %v\n", err)
		os.Exit(1)
	}

	// Retrieve secret (will trigger biometric auth)
	value, err := ls.Get(secretID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving secret '%s': %v\n", secretID, err)
		os.Exit(1)
	}

	// Zero out secret after printing
	defer func() {
		for i := range value {
			value[i] = 0
		}
	}()

	// Output secret value to stdout (Summon provider contract)
	// No newline - Summon expects raw value
	fmt.Print(string(value))
}
