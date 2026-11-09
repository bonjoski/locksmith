package main

import (
	"fmt"
	"os"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
	"github.com/bonjoski/locksmith/v2/pkg/slice"
)

var version string

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		v := version
		if v == "" {
			v = locksmith.Version
		}
		fmt.Printf("summon-locksmith version %s\n", v)
		return 0
	}

	// Summon provider contract: take secret ID as first argument
	// Force silent mode for Summon provider (no expiration warnings)
	if err := os.Setenv("LOCKSMITH_SILENT", "true"); err != nil {
		fmt.Fprintf(os.Stderr, "Error configuring environment: %v\n", err)
		return 1
	}

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: summon-locksmith <secret-id>")
		return 1
	}

	secretID := os.Args[1]

	// Initialize locksmith
	ls, err := locksmith.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing locksmith: %v\n", err)
		return 1
	}
	ls.Options.AuditIdentity = "summon"

	// Retrieve secret (will trigger biometric auth)
	value, err := ls.Get(secretID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving secret '%s': %v\n", secretID, err)
		return 1
	}

	// Zero out secret buffer in RAM without creating an immutable string copy
	defer slice.ExplicitBzero(value)

	// Output raw secret bytes directly to stdout (Summon provider contract: no trailing newline)
	for written := 0; written < len(value); {
		n, writeErr := os.Stdout.Write(value[written:])
		if writeErr != nil {
			fmt.Fprintf(os.Stderr, "Error writing secret to stdout: %v\n", writeErr)
			return 1
		}
		written += n
	}
	return 0
}
