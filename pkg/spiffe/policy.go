package spiffe

import (
	"encoding/json"
	"fmt"
	"os"
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
}

// Policy manages workload identity access control lists.
type Policy struct {
	TrustDomain string       `json:"trust_domain"`
	AllowedUIDs []uint32     `json:"allowed_uids"`
	Rules       []PolicyRule `json:"rules,omitempty"`
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
	return &pol, nil
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

// Authorize validates whether identity is permitted to receive the requested SPIFFE ID.
func (p *Policy) Authorize(identity *CallerIdentity, requestedID *ca.SPIFFEID) error {
	if identity == nil {
		return ErrAttestationFailed
	}

	if !p.isUIDAllowed(identity.UID) {
		return fmt.Errorf("%w: caller UID %d is not in allowed UIDs %v", ErrUnauthorizedWorkload, identity.UID, p.AllowedUIDs)
	}

	if requestedID != nil {
		if requestedID.TrustDomain() != p.TrustDomain {
			return fmt.Errorf("%w: requested trust domain %q does not match authority %q", ErrUnauthorizedWorkload, requestedID.TrustDomain(), p.TrustDomain)
		}
	}

	return nil
}

// ResolveSPIFFEID derives the appropriate SPIFFE ID for an attested workload.
func (p *Policy) ResolveSPIFFEID(identity *CallerIdentity, requested string) (*ca.SPIFFEID, error) {
	if requested != "" {
		parsed, err := ca.ParseSPIFFEID(requested)
		if err != nil {
			return nil, err
		}
		if err := p.Authorize(identity, parsed); err != nil {
			return nil, err
		}
		return parsed, nil
	}

	comm := identity.Comm
	if comm == "" {
		comm = "app"
	}
	cleanComm := strings.ToLower(strings.ReplaceAll(comm, " ", "-"))
	defaultURI := fmt.Sprintf("spiffe://%s/workload/%s", p.TrustDomain, cleanComm)

	parsed, err := ca.ParseSPIFFEID(defaultURI)
	if err != nil {
		return nil, err
	}
	if err := p.Authorize(identity, parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}
