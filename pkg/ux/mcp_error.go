package ux

import (
	"bytes"
	"strings"
)

// Deterministic UB-CLI-v2 / UB-MCP-v1 exit codes.
const (
	ExitRuntimeErr       = 1
	ExitPolicyDeny       = 10
	ExitSupplyChainBlock = 20
	ExitSandboxViolation = 30
	ExitSecretGuardBlock = 40
	ExitBiometricReq     = 82
)

// SelfHealSuggestion carries a machine-readable remediation tool suggestion for AI agents
// conforming to ub-mcp-v1-error.schema.json.
type SelfHealSuggestion struct {
	SuggestedTool         string         `json:"suggested_tool"`
	SuggestedArgs         map[string]any `json:"suggested_args"`
	RequiresHumanApproval bool           `json:"requires_human_approval"`
}

// UBMCPError is the strict UB-MCP-v1 structuredContent error payload conforming to
// ub-mcp-v1-error.schema.json (additionalProperties: false).
type UBMCPError struct {
	SchemaVersion  string              `json:"schema_version"`
	Tool           string              `json:"tool"`
	Code           string              `json:"code"`
	ExitCode       int                 `json:"exit_code"`
	Retryable      bool                `json:"retryable"`
	Summary        string              `json:"summary"`
	RemediationCmd string              `json:"remediation_cmd"`
	Why            string              `json:"why"`
	DeepWhy        string              `json:"deep_why,omitempty"`
	SelfHeal       *SelfHealSuggestion `json:"self_heal,omitempty"`
	ReceiptID      string              `json:"receipt_id,omitempty"`
	References     []string            `json:"references,omitempty"`
}

// Sanitized returns a schema-compliant copy with all text fields ANSI/control-char stripped
// and bounded to the schema length limits.
func (e *UBMCPError) Sanitized() *UBMCPError {
	if e == nil {
		return nil
	}
	tool := sanitizeSingleLine(e.Tool)
	if tool == "" {
		tool = "locksmith"
	}
	schemaVersion := sanitizeSingleLine(e.SchemaVersion)
	if schemaVersion == "" {
		schemaVersion = "ub-cli-v2"
	}
	code := sanitizeSingleLine(e.Code)
	if code == "" {
		code = "LOCKSMITH_RUNTIME_ERROR"
	}
	summary := truncateRunes(sanitizeSingleLine(e.Summary), 240)
	if summary == "" {
		summary = "Locksmith paused this operation."
	}
	remediation := truncateRunes(sanitizeSingleLine(e.RemediationCmd), 256)
	if remediation == "" {
		remediation = "locksmith_checkout_lease"
	}
	why := truncateRunes(sanitizeSingleLine(e.Why), 280)
	if why == "" {
		why = "Operation violated local workstation security invariants."
	}
	out := &UBMCPError{
		SchemaVersion:  schemaVersion,
		Tool:           tool,
		Code:           code,
		ExitCode:       normalizeExitCode(e.ExitCode),
		Retryable:      e.Retryable,
		Summary:        summary,
		RemediationCmd: remediation,
		Why:            why,
		DeepWhy:        truncateRunes(strings.TrimSpace(sanitizeTerminalText(e.DeepWhy)), 2048),
		ReceiptID:      sanitizeSingleLine(e.ReceiptID),
	}
	if e.SelfHeal != nil {
		args := make(map[string]any, len(e.SelfHeal.SuggestedArgs))
		for k, v := range e.SelfHeal.SuggestedArgs {
			if s, ok := v.(string); ok {
				args[sanitizeSingleLine(k)] = sanitizeSingleLine(s)
			} else {
				args[sanitizeSingleLine(k)] = v
			}
		}
		out.SelfHeal = &SelfHealSuggestion{
			SuggestedTool:         sanitizeSingleLine(e.SelfHeal.SuggestedTool),
			SuggestedArgs:         args,
			RequiresHumanApproval: e.SelfHeal.RequiresHumanApproval,
		}
	}
	if len(e.References) > 0 {
		out.References = make([]string, 0, len(e.References))
		for _, ref := range e.References {
			if clean := sanitizeSingleLine(ref); clean != "" {
				out.References = append(out.References, clean)
			}
		}
	}
	return out
}

// HumanText renders a calm <=3-line human-readable message suitable for MCP content[0].text.
func (e *UBMCPError) HumanText() string {
	s := e.Sanitized()
	if s == nil {
		return ""
	}
	ff := &FixForwardError{
		Tool:           s.Tool,
		Code:           s.Code,
		Summary:        s.Summary,
		RemediationCmd: s.RemediationCmd,
		WhyOneLiner:    s.Why,
		ExitCode:       s.ExitCode,
	}
	var buf bytes.Buffer
	_ = ff.Render(&buf, false, false)
	return strings.TrimRight(buf.String(), "\n")
}

func normalizeExitCode(code int) int {
	switch code {
	case ExitRuntimeErr, ExitPolicyDeny, ExitSupplyChainBlock, ExitSandboxViolation, ExitSecretGuardBlock, ExitBiometricReq:
		return code
	default:
		return ExitRuntimeErr
	}
}

func truncateRunes(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen])
}
