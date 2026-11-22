package ux

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// FixForwardError enforces the UB-CLI-v2 "Teach, Don't Scold" error invariant.
type FixForwardError struct {
	Tool           string   `json:"tool"`
	Code           string   `json:"code"`
	Summary        string   `json:"summary"`
	RemediationCmd string   `json:"remediation_cmd"`
	WhyOneLiner    string   `json:"why"`
	DeepWhy        string   `json:"deep_why,omitempty"`
	References     []string `json:"references,omitempty"`
	ExitCode       int      `json:"exit_code"`
}

func (e *FixForwardError) Error() string {
	if e == nil {
		return ""
	}
	return sanitizeSingleLine(e.Summary)
}

func (e *FixForwardError) renderJSON(w io.Writer) error {
	sanitized := FixForwardError{
		Tool:           sanitizeSingleLine(e.Tool),
		Code:           sanitizeSingleLine(e.Code),
		Summary:        sanitizeSingleLine(e.Summary),
		RemediationCmd: sanitizeSingleLine(e.RemediationCmd),
		WhyOneLiner:    sanitizeSingleLine(e.WhyOneLiner),
		DeepWhy:        sanitizeTerminalText(e.DeepWhy),
		ExitCode:       e.ExitCode,
	}
	if len(e.References) > 0 {
		sanitized.References = make([]string, len(e.References))
		for i, ref := range e.References {
			sanitized.References[i] = sanitizeSingleLine(ref)
		}
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(&sanitized)
}

func (e *FixForwardError) renderDeepWhy(w io.Writer, deepWhy string) error {
	if _, err := fmt.Fprintf(w, "\n  Deep Dive (--why):\n  %s\n", strings.ReplaceAll(deepWhy, "\n", "\n  ")); err != nil {
		return err
	}
	for _, ref := range e.References {
		if cleanRef := sanitizeSingleLine(ref); cleanRef != "" {
			if _, err := fmt.Fprintf(w, "  Ref:  %s\n", cleanRef); err != nil {
				return err
			}
		}
	}
	return nil
}

// Render writes machine-readable single-line JSON (--json), calm <=3-line default output,
// or full progressive-disclosure output (--why). All strings are ANSI/control-char sanitized.
func (e *FixForwardError) Render(w io.Writer, asJSON bool, showWhy bool) error {
	if e == nil {
		return nil
	}
	if asJSON {
		return e.renderJSON(w)
	}
	tool := sanitizeSingleLine(e.Tool)
	if tool == "" {
		tool = "locksmith"
	}
	if _, err := fmt.Fprintf(w, "⚠ %s: %s\n", tool, sanitizeSingleLine(e.Summary)); err != nil {
		return err
	}
	if fix := sanitizeSingleLine(e.RemediationCmd); fix != "" {
		if _, err := fmt.Fprintf(w, "  Fix:  %s\n", fix); err != nil {
			return err
		}
	}
	deepWhy := strings.TrimSpace(sanitizeTerminalText(e.DeepWhy))
	if whyLine := formatWhyLine(sanitizeSingleLine(e.WhyOneLiner), deepWhy, showWhy); whyLine != "" {
		if _, err := fmt.Fprintf(w, "  Why:  %s\n", whyLine); err != nil {
			return err
		}
	}
	if showWhy && deepWhy != "" {
		return e.renderDeepWhy(w, deepWhy)
	}
	return nil
}

func formatWhyLine(why, deepWhy string, showWhy bool) string {
	if why == "" && (showWhy || deepWhy == "") {
		return ""
	}
	if !showWhy && deepWhy != "" {
		if why != "" {
			return fmt.Sprintf("%s (re-run with --why for details)", why)
		}
		return "Re-run with --why for details."
	}
	return why
}

var remediationTokenRe = regexp.MustCompile(`^[a-zA-Z0-9@._/-]+$`)

// ValidateRemediationToken restricts interpolated CLI tokens to a strict ASCII allowlist.
func ValidateRemediationToken(token string) bool {
	if token == "" || len(token) > 214 {
		return false
	}
	if !remediationTokenRe.MatchString(token) {
		return false
	}
	if strings.HasPrefix(token, "-") || strings.HasPrefix(token, "/") || strings.HasSuffix(token, "/") {
		return false
	}
	if strings.Contains(token, "..") || strings.Contains(token, "//") {
		return false
	}
	return true
}

// SanitizeTerminalText strips ESC, CSI, OSC, DCS/SOS/PM/APC, C0/C1 controls, DEL, and bidi overrides.
func SanitizeTerminalText(s string) string {
	return sanitizeTerminalText(s)
}

func sanitizeSingleLine(s string) string {
	clean := sanitizeTerminalText(s)
	clean = strings.ReplaceAll(clean, "\n", " ")
	clean = strings.ReplaceAll(clean, "\t", " ")
	return strings.TrimSpace(clean)
}

func skipCSI(runes []rune, i int) int {
	for i < len(runes) {
		if runes[i] >= 0x40 && runes[i] <= 0x7e {
			return i
		}
		i++
	}
	return i
}

func skipStringSeq(runes []rune, i int) int {
	for i < len(runes) {
		if runes[i] == 0x07 || runes[i] == 0x9c {
			return i
		}
		if runes[i] == 0x1b && i+1 < len(runes) && runes[i+1] == '\\' {
			return i + 1
		}
		i++
	}
	return i
}

func skipEscSeq(runes []rune, i int) int {
	if i+1 >= len(runes) {
		return len(runes)
	}
	switch runes[i+1] {
	case '[':
		return skipCSI(runes, i+2)
	case ']', 'P', 'X', '^', '_':
		return skipStringSeq(runes, i+2)
	default:
		i++
		for i < len(runes) && runes[i] >= 0x20 && runes[i] <= 0x2f {
			i++
		}
		return i
	}
}

func isC1StringIntro(r rune) bool {
	return r == 0x9d || r == 0x90 || r == 0x98 || r == 0x9e || r == 0x9f
}

func isAllowedTerminalRune(r rune) bool {
	if r == '\n' || r == '\t' {
		return true
	}
	if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
		return false
	}
	if (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
		return false
	}
	return true
}

func sanitizeTerminalText(s string) string {
	runes := []rune(s)
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == 0x1b {
			i = skipEscSeq(runes, i)
			continue
		}
		if r == 0x9b {
			i = skipCSI(runes, i+1)
			continue
		}
		if isC1StringIntro(r) {
			i = skipStringSeq(runes, i+1)
			continue
		}
		if isAllowedTerminalRune(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
