package main

import (
	"fmt"
	"os"

	"github.com/bonjoski/locksmith/pkg/locksmith"
)

func main() {
	// Summon provider contract: take secret ID as first argument
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Error: No secret identifier provided")
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
