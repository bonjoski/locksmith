package spiffe

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
)

// DefaultTrustDomain is the standard sovereign local trust domain.
const DefaultTrustDomain = "bonjoski.local"

// PolicyRule defines attestation constraints for matching SPIFFE patterns.
type PolicyRule struct {
	SPIFFEPattern   string   `json:"spiffe_pattern"`
	AllowedUIDs     []uint32 `json:"allowed_uids,omitempty"`
	AllowedBinaries []string `json:"allowed_binaries,omitempty"`
	AllowedCIDs     []uint32 `json:"allowed_cids,omitempty"`
}

// Policy manages workload identity access control lists.
type Policy struct {
	TrustDomain string       `json:"trust_domain"`
	AllowedUIDs []uint32     `json:"allowed_uids"`
	AllowedCIDs []uint32     `json:"allowed_cids,omitempty"`
	Rules       []PolicyRule `json:"rules,omitempty"`
	warnings    []string     `json:"-"`
}

// NewDefaultPolicy initializes a policy allowing the current user UID.
func NewDefaultPolicy(trustDomain string) *Policy {
	if trustDomain == "" {
		trustDomain = DefaultTrustDomain
	}
	return &Policy{
		TrustDomain: trustDomain,
		AllowedUIDs: []uint32{uint32(os.Getuid())},
	}
}

// LoadPolicy reads and parses a JSON policy file, or returns the default policy if not found.
func LoadPolicy(path string, trustDomain string) (*Policy, error) {
	if path == "" {
		return NewDefaultPolicy(trustDomain), nil
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return NewDefaultPolicy(trustDomain), nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed reading policy %s: %w", path, err)
	}

	var pol Policy
	if err := json.Unmarshal(data, &pol); err != nil {
		return nil, fmt.Errorf("failed parsing policy JSON: %w", err)
	}
	if pol.TrustDomain == "" {
		pol.TrustDomain = DefaultTrustDomain
	}
	warnings, err := pol.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	pol.warnings = warnings
	return &pol, nil
}

// Warnings returns any non-fatal security warnings identified during policy validation.
func (p *Policy) Warnings() []string {
	if p == nil || len(p.warnings) == 0 {
		return nil
	}
	res := make([]string, len(p.warnings))
	copy(res, p.warnings)
	return res
}

// Validate checks policy rules and returns any security warnings or fatal validation errors.
func (p *Policy) Validate() ([]string, error) {
	if p.TrustDomain == "" {
		return nil, errors.New("policy trust_domain must not be empty")
	}
	var warnings []string
	for _, rule := range p.Rules {
		if rule.SPIFFEPattern == "" {
			return nil, errors.New("policy rule spiffe_pattern must not be empty")
		}
		for _, bin := range rule.AllowedBinaries {
			lower := strings.ToLower(bin)
			if !strings.HasPrefix(lower, "sha256:") && !isHex64(bin) {
				if !strings.HasPrefix(lower, "path:") && !strings.HasPrefix(lower, "comm:") {
					return nil, fmt.Errorf("rule for %q uses unauthenticated bare binary identifier %q; must specify sha256:<digest>, path:<path>, or comm:<name>", rule.SPIFFEPattern, bin)
				}
				warnings = append(warnings, fmt.Sprintf("rule for %q uses unauthenticated %s provenance %q; only sha256 digests provide non-repudiable attestation", rule.SPIFFEPattern, bin[:4], bin))
			}
		}
	}
	return warnings, nil
}

func (p *Policy) isUIDAllowed(uid uint32) bool {
	if len(p.AllowedUIDs) == 0 {
		return uid == uint32(os.Getuid())
	}
	for _, allowed := range p.AllowedUIDs {
		if allowed == uid {
			return true
		}
	}
	return false
}

func (p *Policy) isCIDAllowed(cid uint32) bool {
	if len(p.AllowedCIDs) == 0 {
		return false // fail-closed: must explicitly configure allowed CIDs
	}
	for _, allowed := range p.AllowedCIDs {
		if allowed == cid {
			return true
		}
	}
	return false
}

func matchPattern(pattern, target string) bool {
	if pattern == target {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if strings.HasPrefix(target, prefix+"/") {
			return true
		}
	}
	if matched, err := filepath.Match(pattern, target); err == nil && matched {
		return true
	}
	return false
}

func (p *Policy) hasExplicitCIDRule(cid uint32, spiffeID string) bool {
	for _, rule := range p.Rules {
		if matchPattern(rule.SPIFFEPattern, spiffeID) {
			for _, allowedCID := range rule.AllowedCIDs {
				if allowedCID == cid {
					return true
				}
			}
		}
	}
	return false
}

func matchesUID(allowedUIDs []uint32, uid uint32) bool {
	if len(allowedUIDs) == 0 {
		return true
	}
	for _, u := range allowedUIDs {
		if u == uid {
			return true
		}
	}
	return false
}

func matchesCID(allowedCIDs []uint32, cid uint32) bool {
	if len(allowedCIDs) == 0 {
		return true
	}
	for _, c := range allowedCIDs {
		if c == cid {
			return true
		}
	}
	return false
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func matchPrefixedBinary(lower, binSpec string, id *CallerIdentity) bool {
	switch {
	case strings.HasPrefix(lower, "sha256:"):
		return id.ExeHash != "" && strings.EqualFold(id.ExeHash, binSpec)
	case isHex64(binSpec):
		return id.ExeHash != "" && strings.EqualFold(id.ExeHash, "sha256:"+binSpec)
	case strings.HasPrefix(lower, "path:"):
		return id.ExePath != "" && id.ExePath == binSpec[5:]
	case strings.HasPrefix(lower, "comm:"):
		return id.Comm != "" && id.Comm == binSpec[5:]
	default:
		return false
	}
}

func matchesSingleBinary(binSpec string, id *CallerIdentity) bool {
	if binSpec == "" || id == nil {
		return false
	}
	lower := strings.ToLower(binSpec)
	return matchPrefixedBinary(lower, binSpec, id)
}

func matchesBinary(allowedBinaries []string, id *CallerIdentity) bool {
	if len(allowedBinaries) == 0 {
		return true
	}
	for _, bin := range allowedBinaries {
		if matchesSingleBinary(bin, id) {
			return true
		}
	}
	return false
}

func ruleSatisfiesCaller(rule PolicyRule, reqStr string, id *CallerIdentity) bool {
	if !matchPattern(rule.SPIFFEPattern, reqStr) {
		return false
	}
	if !matchesUID(rule.AllowedUIDs, id.UID) {
		return false
	}
	if !matchesCID(rule.AllowedCIDs, id.VsockCID) {
		return false
	}
	return matchesBinary(rule.AllowedBinaries, id)
}

func (p *Policy) checkBasicCallerAccess(identity *CallerIdentity) error {
	if identity.VsockCID > 0 {
		if !p.isCIDAllowed(identity.VsockCID) {
			return fmt.Errorf("%w: caller vsock CID %d is not in allowed CIDs %v", ErrUnauthorizedWorkload, identity.VsockCID, p.AllowedCIDs)
		}
		return nil
	}
	if !p.isUIDAllowed(identity.UID) {
		return fmt.Errorf("%w: caller UID %d is not in allowed UIDs %v", ErrUnauthorizedWorkload, identity.UID, p.AllowedUIDs)
	}
	return nil
}

// DefaultSPIFFEIDForIdentity computes the canonical default SPIFFE URI for an attested caller.
func (p *Policy) DefaultSPIFFEIDForIdentity(identity *CallerIdentity) string {
	if identity != nil && identity.VsockCID > 0 {
		return fmt.Sprintf("spiffe://%s/vm/cid/%d", p.TrustDomain, identity.VsockCID)
	}
	comm := "app"
	if identity != nil && identity.Comm != "" {
		comm = identity.Comm
	}
	cleanComm := strings.ToLower(strings.ReplaceAll(comm, " ", "-"))
	return fmt.Sprintf("spiffe://%s/workload/%s", p.TrustDomain, cleanComm)
}

func (p *Policy) authorizeAgainstRules(reqStr string, identity *CallerIdentity) error {
	if len(p.Rules) == 0 {
		defaultID := p.DefaultSPIFFEIDForIdentity(identity)
		if reqStr != defaultID {
			return fmt.Errorf("%w: requested SPIFFE ID %q requires an explicit policy rule (caller default is %q)", ErrUnauthorizedWorkload, reqStr, defaultID)
		}
		return nil
	}
	for _, rule := range p.Rules {
		if ruleSatisfiesCaller(rule, reqStr, identity) {
			return nil
		}
	}
	return fmt.Errorf("%w: no policy rule authorizes caller (UID=%d, Comm=%s) for requested SPIFFE ID %q", ErrUnauthorizedWorkload, identity.UID, identity.Comm, reqStr)
}

// Authorize validates whether identity is permitted to receive the requested SPIFFE ID.
func (p *Policy) Authorize(identity *CallerIdentity, requestedID *ca.SPIFFEID) error {
	if identity == nil {
		return ErrAttestationFailed
	}
	if err := p.checkBasicCallerAccess(identity); err != nil {
		return err
	}
	if requestedID == nil {
		return nil
	}
	if requestedID.TrustDomain() != p.TrustDomain {
		return fmt.Errorf("%w: requested trust domain %q does not match authority %q", ErrUnauthorizedWorkload, requestedID.TrustDomain(), p.TrustDomain)
	}
	return p.authorizeAgainstRules(requestedID.String(), identity)
}

// ResolveSPIFFEID derives the appropriate SPIFFE ID for an attested workload.
func (p *Policy) ResolveSPIFFEID(identity *CallerIdentity, requested string) (*ca.SPIFFEID, error) {
	if requested != "" {
		parsed, err := ca.ParseSPIFFEID(requested)
		if err != nil {
			return nil, err
		}
		if identity != nil && identity.VsockCID > 0 {
			expectedCIDURI := fmt.Sprintf("spiffe://%s/vm/cid/%d", p.TrustDomain, identity.VsockCID)
			if parsed.String() != expectedCIDURI {
				if !p.hasExplicitCIDRule(identity.VsockCID, parsed.String()) {
					return nil, fmt.Errorf("%w: microVM CID %d is not authorized for requested SPIFFE ID %q (pinned to %s)", ErrUnauthorizedWorkload, identity.VsockCID, requested, expectedCIDURI)
				}
			}
		}
		if err := p.Authorize(identity, parsed); err != nil {
			return nil, err
		}
		return parsed, nil
	}

	defaultURI := p.DefaultSPIFFEIDForIdentity(identity)
	parsed, err := ca.ParseSPIFFEID(defaultURI)
	if err != nil {
		return nil, err
	}
	if err := p.Authorize(identity, parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}
