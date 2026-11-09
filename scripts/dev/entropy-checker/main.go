package main

import (
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var skippedPathOrURLPrefixes = []string{
	"http://",
	"https://",
	"./",
	"../",
	"/Users/",
	"/var/",
	"/tmp/",
	"/etc/",
	"github.com/",
	"golang.org/",
}

func isKnownSafePathOrURL(s string) bool {
	for _, p := range skippedPathOrURLPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// calculateEntropy computes the Shannon entropy of a string over UTF-8 runes.
func calculateEntropy(data string) float64 {
	runeLen := utf8.RuneCountInString(data)
	if runeLen == 0 {
		return 0
	}
	charCounts := make(map[rune]int, runeLen)
	for _, char := range data {
		charCounts[char]++
	}
	entropy := 0.0
	total := float64(runeLen)
	for _, count := range charCounts {
		p := float64(count) / total
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
	if parsed, err := strconv.ParseFloat(os.Args[1], 64); err == nil && parsed > 0 {
		threshold = parsed
	}

	found := false
	alphaRegex := regexp.MustCompile(`^[A-Za-z]+$`)
	for _, arg := range os.Args[2:] {
		// Only check strings at least 16 runes long (heuristic for tokens/keys)
		if utf8.RuneCountInString(arg) < 16 {
			continue
		}
		// Skip explicit URLs and filesystem/module path prefixes without skipping Base64 secrets containing '/'
		if isKnownSafePathOrURL(arg) {
			continue
		}
		// Skip pure alphabetic identifiers (e.g., constant names) which are unlikely to be secrets
		if alphaRegex.MatchString(arg) {
			continue
		}
		e := calculateEntropy(arg)
		if e >= threshold {
			fmt.Printf("[High Entropy Gate] Suspicious secret string found (entropy: %.2f): %s\n", e, arg)
			found = true
		}
	}

	if found {
		os.Exit(1)
	}
}
