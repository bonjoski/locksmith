package main

import (
	"fmt"
	"math"
	"os"
)

// calculateEntropy computes the Shannon entropy of a string.
func calculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}
	charCounts := make(map[rune]int)
	for _, char := range data {
		charCounts[char]++
	}
	entropy := 0.0
	for _, count := range charCounts {
		p := float64(count) / float64(len(data))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: entropy-checker <threshold> <strings...>")
		os.Exit(1)
	}

	threshold := 4.5 // Default threshold
	_, _ = fmt.Sscanf(os.Args[1], "%f", &threshold)

	found := false
	for _, arg := range os.Args[2:] {
		// Only check strings longer than 16 chars (heuristic for tokens/keys)
		if len(arg) < 16 {
			continue
		}
		e := calculateEntropy(arg)
		if e > threshold {
			fmt.Printf("[Low Entropy Gate] Suspicious string found (entropy: %.2f): %s\n", e, arg)
			found = true
		}
	}

	if found {
		os.Exit(1)
	}
}
