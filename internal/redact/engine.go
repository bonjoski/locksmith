package redact

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

var (
	// ErrSecretLeakageDetected is returned by FailClosedWireGuard if unredacted secrets escape.
	ErrSecretLeakageDetected = errors.New("fail-closed wire guard: unredacted secret detected in outbound payload")

	placeholderRegex = regexp.MustCompile(`\[SECRET_REF_[0-9a-fA-F]{16}\]`)
)

// Config configures the detection and redaction behavior of the Engine.
type Config struct {
	MinEntropyLen    int               // Minimum length of candidate token to check entropy (default: 16)
	EntropyThreshold float64           // Shannon entropy threshold (default: 4.2)
	Patterns         []SecretPattern   // Regex secret detection patterns
	CustomVaultKeys  map[string]string // Known credentials mapped by name
}

// DefaultConfig returns the production baseline configuration.
func DefaultConfig() Config {
	patterns := make([]SecretPattern, len(BuiltinPatterns))
	copy(patterns, BuiltinPatterns)
	return Config{
		MinEntropyLen:    16,
		EntropyThreshold: 4.2,
		Patterns:         patterns,
		CustomVaultKeys:  make(map[string]string),
	}
}

// Engine performs local pre-flight secret tokenization and fail-closed wire checking.
type Engine struct {
	cfg Config
}

// NewEngine initializes a redaction engine with the provided configuration.
func NewEngine(cfg Config) *Engine {
	if cfg.MinEntropyLen == 0 {
		cfg.MinEntropyLen = 16
	}
	if cfg.EntropyThreshold == 0.0 {
		cfg.EntropyThreshold = 4.2
	}
	if len(cfg.Patterns) == 0 {
		cfg.Patterns = make([]SecretPattern, len(BuiltinPatterns))
		copy(cfg.Patterns, BuiltinPatterns)
	}
	if cfg.CustomVaultKeys == nil {
		cfg.CustomVaultKeys = make(map[string]string)
	}
	return &Engine{cfg: cfg}
}

// isInvisibleFormatRune returns true for Unicode Format (Cf), Variation Selectors,
// Unicode Tags (U+E0000..U+E007F), soft hyphens, bidi overrides, and invisible fillers
// used by adversaries to split secret tokens and evade regex/entropy inspection.
func isInvisibleFormatRune(r rune) bool {
	if unicode.Is(unicode.Cf, r) {
		return true
	}
	if (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF) {
		return true
	}
	if r >= 0xE0000 && r <= 0xE007F {
		return true
	}
	switch r {
	case 0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x3164, 0xFFA0:
		return true
	}
	return false
}

// normalizeInvisibleChars strips zero-width, format (Cf), tag, and variation-selector
// unicode characters used by adversaries attempting to evade regex matching and entropy checks.
func normalizeInvisibleChars(s string) string {
	return strings.Map(func(r rune) rune {
		if isInvisibleFormatRune(r) {
			return -1
		}
		return r
	}, s)
}

type vaultEntry struct {
	name   string
	secret string
}

func (e *Engine) sortedVaultEntries() []vaultEntry {
	entries := make([]vaultEntry, 0, len(e.cfg.CustomVaultKeys))
	for name, secret := range e.cfg.CustomVaultKeys {
		if len(secret) < 4 {
			continue
		}
		entries = append(entries, vaultEntry{name: name, secret: secret})
	}
	sort.Slice(entries, func(i, j int) bool {
		if len(entries[i].secret) != len(entries[j].secret) {
			return len(entries[i].secret) > len(entries[j].secret)
		}
		if entries[i].secret != entries[j].secret {
			return entries[i].secret < entries[j].secret
		}
		return entries[i].name < entries[j].name
	})
	return entries
}

func isNonSecretAssignmentValue(val string) bool {
	lower := strings.ToLower(strings.TrimSpace(val))
	switch lower {
	case "", "true", "false", "null", "none", "nil", "undefined", "redacted", "[redacted]", "redacted_secret", "[redacted_secret]", "[redacted_secret":
		return true
	}
	if strings.Contains(val, "[SECRET_REF_") || strings.Contains(val, "[REDACTED_SECRET]") {
		return true
	}
	if strings.HasPrefix(val, "${") || strings.HasPrefix(val, "os.Getenv(") || strings.HasPrefix(val, "process.env.") {
		return true
	}
	return false
}

func isTokenDelimiter(r rune) bool {
	if unicode.IsSpace(r) {
		return true
	}
	switch r {
	case '"', '\'', '`', '=', ':', ';', ',', '&', '?', '/', '\\', '(', ')', '{', '}', '<', '>', '|':
		return true
	}
	return false
}

func extractCandidateSegments(s string) []string {
	masked := placeholderRegex.ReplaceAllString(s, " ")
	masked = strings.ReplaceAll(masked, "[REDACTED_SECRET]", " ")
	rawFields := strings.FieldsFunc(masked, isTokenDelimiter)
	out := make([]string, 0, len(rawFields))
	for _, f := range rawFields {
		cleaned := strings.Trim(f, `"',;:()[]{}<>`)
		if cleaned == "" || strings.Contains(cleaned, "[SECRET_REF_") || strings.Contains(cleaned, "[REDACTED_SECRET]") {
			continue
		}
		out = append(out, cleaned)
	}
	return out
}

// Redact scans the input string, substitutes all discovered secrets with opaque
// placeholders (e.g. "[SECRET_REF_e7a9b1c2d3e4f501]"), and stores mappings in a new TokenMap.
func (e *Engine) Redact(input string) (string, *TokenMap, error) {
	tm := NewTokenMap()
	out, err := e.RedactWithTokenMap(input, tm)
	if err != nil {
		tm.Zeroize()
		return "", nil, err
	}
	return out, tm, nil
}

func (e *Engine) applyPatternRedaction(output string, tm *TokenMap) string {
	for _, p := range e.cfg.Patterns {
		for _, m := range p.Regex.FindAllStringSubmatch(output, -1) {
			if len(m) == 0 {
				continue
			}
			candidate := m[0]
			if len(m) > 1 && len(m[1]) > 0 {
				candidate = m[1]
			}
			if isNonSecretAssignmentValue(candidate) {
				continue
			}
			if p.Entropy > 0 && !IsHighEntropy(candidate, p.MinLen, p.Entropy) {
				continue
			}
			ref := tm.Add(candidate, p.Name)
			output = strings.ReplaceAll(output, candidate, ref)
		}
	}
	return output
}

func (e *Engine) applyEntropyRedaction(output string, tm *TokenMap) string {
	segments := extractCandidateSegments(output)
	sort.Slice(segments, func(i, j int) bool {
		return len(segments[i]) > len(segments[j])
	})
	for _, seg := range segments {
		if !strings.Contains(output, seg) {
			continue
		}
		if IsHighEntropy(seg, e.cfg.MinEntropyLen, e.cfg.EntropyThreshold) {
			ref := tm.Add(seg, "High-Entropy Token")
			output = strings.ReplaceAll(output, seg, ref)
		}
	}
	return output
}

// RedactWithTokenMap scans input using a caller-supplied TokenMap so all fields/messages
// within a single request share consistent placeholder tokens.
func (e *Engine) RedactWithTokenMap(input string, tm *TokenMap) (string, error) {
	if tm == nil {
		return "", errors.New("redact: TokenMap must not be nil")
	}
	output := normalizeInvisibleChars(input)
	for _, entry := range e.sortedVaultEntries() {
		if strings.Contains(output, entry.secret) {
			ref := tm.Add(entry.secret, entry.name)
			output = strings.ReplaceAll(output, entry.secret, ref)
		}
	}
	output = e.applyPatternRedaction(output, tm)
	output = e.applyEntropyRedaction(output, tm)
	return output, nil
}

// Restore substitutes all placeholder tokens in text back to their original secret values.
// Handles nested placeholder substitutions iteratively until all placeholders are resolved.
func (e *Engine) Restore(text string, tm *TokenMap) string {
	if tm == nil {
		return text
	}

	result := text
	for pass := 0; pass < 5; pass++ {
		changed := false
		for _, ref := range tm.References() {
			if strings.Contains(result, ref) {
				if secret, ok := tm.GetSecret(ref); ok {
					result = strings.ReplaceAll(result, ref, secret)
					changed = true
				}
			}
		}
		if !changed || !strings.Contains(result, "[SECRET_REF_") {
			break
		}
	}
	return result
}

func checkPatternLeakage(s string, p SecretPattern) error {
	if len(p.Regex.SubexpNames()) > 1 {
		for _, m := range p.Regex.FindAllStringSubmatch(s, -1) {
			if len(m) > 1 && len(m[1]) > 0 && !isNonSecretAssignmentValue(m[1]) {
				return fmt.Errorf("%w: unshielded credential in %s", ErrSecretLeakageDetected, p.Name)
			}
		}
		return nil
	}
	for _, m := range p.Regex.FindAllString(s, -1) {
		if !strings.Contains(m, "[SECRET_REF_") {
			return fmt.Errorf("%w: matched %s", ErrSecretLeakageDetected, p.Name)
		}
	}
	return nil
}

// FailClosedWireGuard performs a final safety check on the serialized payload before
// transmission over the network. If any unredacted pattern or high-entropy token is found,
// the outbound call aborts immediately.
func (e *Engine) FailClosedWireGuard(payload []byte) error {
	s := normalizeInvisibleChars(string(payload))
	for _, entry := range e.sortedVaultEntries() {
		if strings.Contains(s, entry.secret) {
			return fmt.Errorf("%w: matched custom vault key %s", ErrSecretLeakageDetected, entry.name)
		}
	}
	for _, p := range e.cfg.Patterns {
		if err := checkPatternLeakage(s, p); err != nil {
			return err
		}
	}
	for _, seg := range extractCandidateSegments(s) {
		if IsHighEntropy(seg, e.cfg.MinEntropyLen, e.cfg.EntropyThreshold) {
			return fmt.Errorf("%w: high-entropy secret segment escaped redaction", ErrSecretLeakageDetected)
		}
	}
	return nil
}
