package redact

import "regexp"

// SecretPattern defines a regex pattern paired with an identification label.
type SecretPattern struct {
	Name    string
	Regex   *regexp.Regexp
	MinLen  int
	Entropy float64
}

// BuiltinPatterns provides curated high-fidelity detection rules for credentials.
var BuiltinPatterns = []SecretPattern{
	{
		Name:  "AWS Access Key ID",
		Regex: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	},
	{
		Name:  "Anthropic API Key",
		Regex: regexp.MustCompile(`\bsk-ant-[a-zA-Z0-9_\-]{20,}\b`),
	},
	{
		Name:  "OpenAI API Key",
		Regex: regexp.MustCompile(`\bsk-(?:proj-|svcacct-|admin-)?[a-zA-Z0-9_\-]{20,}\b`),
	},
	{
		Name:  "Google API Key",
		Regex: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`),
	},
	{
		Name:  "GitHub Personal or App Token",
		Regex: regexp.MustCompile(`\bgh[pousr]_[a-zA-Z0-9]{36,255}\b`),
	},
	{
		Name:  "GitHub Fine-Grained Token",
		Regex: regexp.MustCompile(`\bgithub_pat_[a-zA-Z0-9_]{22,255}\b`),
	},
	{
		Name:  "Slack Token",
		Regex: regexp.MustCompile(`\bxox[baprs]-[0-9a-zA-Z\-]{10,128}\b`),
	},
	{
		Name:  "Database Connection URI",
		Regex: regexp.MustCompile(`\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):\/\/[^:\s]+:([^@\s]+)@[^\s"']+\b`),
	},
	{
		Name:  "Private Key Block",
		Regex: regexp.MustCompile(`-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED|ED25519) )?PRIVATE KEY-----[\s\S]+?-----END (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED|ED25519) )?PRIVATE KEY-----`),
	},
	{
		Name:  "Private Key Header",
		Regex: regexp.MustCompile(`-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED|ED25519) )?PRIVATE KEY-----[^\r\n]*[\r\n]+[A-Za-z0-9+/=\r\n\s]{16,}`),
	},
	{
		Name:  "JSON Web Token",
		Regex: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b`),
	},
	{
		Name:  "Bearer Authorization Token",
		Regex: regexp.MustCompile(`(?i)\bBearer\s+([A-Za-z0-9\-._~+/]{12,}=*)`),
	},
	{
		Name:  "Generic Key Assignment",
		Regex: regexp.MustCompile(`(?i)(?:api[_-]?key|secret(?:[_-]?key)?|password|passwd|pwd|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|token|bearer|credential)\s*[:=]\s*["']([^"'\r\n]{8,})["']`),
	},
	{
		Name:  "Unquoted Key Assignment",
		Regex: regexp.MustCompile(`(?i)\b(?:[a-z0-9_.-]*[_.-])?(?:api[_-]?key|secret(?:[_-]?key)?|password|passwd|pwd|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|token|credential)\s*[:=]\s*([^\s"'` + "`" + `,;)}\]]{8,})`),
	},
}
