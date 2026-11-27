package redact

import (
	"math"
	"unicode"
)

// ShannonEntropy calculates the Shannon entropy of a string in bits per character.
// Strings with high randomness (like cryptographic keys and tokens) typically score > 4.2.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	freq := make(map[rune]float64)
	runeCount := 0
	for _, c := range s {
		freq[c]++
		runeCount++
	}
	if runeCount == 0 {
		return 0.0
	}

	length := float64(runeCount)
	var entropy float64
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// IsHighEntropy returns true if the candidate token exceeds the minimum entropy threshold
// and has sufficient length to qualify as a suspected cryptographic credential.
// To defeat entropy-dilution attacks (e.g. padding a random secret with repeated 'A's),
// longer tokens are also inspected with a sliding window.
func IsHighEntropy(s string, minLen int, threshold float64) bool {
	runes := []rune(s)
	if len(runes) < minLen {
		return false
	}
	if ShannonEntropy(s) >= threshold {
		return true
	}

	// Sliding window scan to defeat low-entropy padding dilution (e.g. "AAAA...<secret>...AAAA").
	winLen := minLen
	if winLen < 24 {
		winLen = 24
	}
	if len(runes) <= winLen {
		return false
	}

	winThreshold := threshold
	if winThreshold < 4.3 {
		winThreshold = 4.3
	}

	for start := 0; start+winLen <= len(runes); start++ {
		window := runes[start : start+winLen]
		if !hasSecretCharacterDiversity(window) {
			continue
		}
		if shannonEntropyRunes(window) >= winThreshold {
			return true
		}
	}
	return false
}

func shannonEntropyRunes(runes []rune) float64 {
	if len(runes) == 0 {
		return 0.0
	}
	freq := make(map[rune]int, len(runes))
	for _, r := range runes {
		freq[r]++
	}
	length := float64(len(runes))
	var entropy float64
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// hasSecretCharacterDiversity ensures sliding windows only flag strings with mixed
// character classes (e.g. digits/symbols/mixed case) rather than plain prose phrases.
func hasSecretCharacterDiversity(runes []rune) bool {
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range runes {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	classes := 0
	if hasLower {
		classes++
	}
	if hasUpper {
		classes++
	}
	if hasDigit {
		classes++
	}
	if hasSymbol {
		classes++
	}
	return classes >= 3 || (hasDigit && (hasLower || hasUpper))
}
