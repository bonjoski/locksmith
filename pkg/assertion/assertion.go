// Package assertion implements hardware-rooted WebAuthn/FIDO2 and RFC 7523
// OAuth 2.0 client assertion synthesis for sovereign agentic identity brokers.
package assertion

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// RFC 7523 OAuth 2.0 Client Assertion constants.
const (
	AssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	AssertionTypeWebAuthn  = "webauthn.assertion"
	DefaultValidity        = 60 * time.Second
	MaxValidity            = 5 * time.Minute
)

// ClientAssertionRequest specifies parameters for minting a client assertion.
type ClientAssertionRequest struct {
	Audience string         `json:"audience"` // Target IdP token endpoint URL
	Subject  string         `json:"subject"`  // Developer identity or agent SPIFFE ID
	Nonce    string         `json:"nonce"`    // Anti-replay challenge from IdP
	KeyTag   string         `json:"key_tag"`  // Hardware key alias / Enclave tag
	Validity time.Duration  `json:"validity"` // Token lifetime (default 60s, max 5m)
	Format   string         `json:"format"`   // "jwt" (default) or "webauthn"
	Claims   map[string]any `json:"claims"`   // Additional posture or metadata claims
}

// ClientAssertionResponse contains the synthesized client assertion.
type ClientAssertionResponse struct {
	AssertionType  string    `json:"assertion_type"`
	AssertionToken string    `json:"client_assertion"`
	ExpiresAt      time.Time `json:"expires_at"`
	KeyID          string    `json:"kid"`
	Algorithm      string    `json:"alg"`
}

// JWTHeader represents the JOSE header for ES256.
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// JWTClaims represents standard and custom RFC 7523 claims.
type JWTClaims struct {
	Issuer         string         `json:"iss"`
	Subject        string         `json:"sub"`
	Audience       string         `json:"aud"`
	JWTID          string         `json:"jti"`
	ExpirationTime int64          `json:"exp"`
	IssuedAt       int64          `json:"iat"`
	NotBefore      int64          `json:"nbf"`
	ExtraClaims    map[string]any `json:"extra,omitempty"`
}

// base64URLEncode encodes bytes without padding.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64URLDecode decodes unpadded base64url data.
func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ComputeKeyID generates a deterministic thumbprint for a P-256 public key.
func ComputeKeyID(pub *ecdsa.PublicKey) string {
	h := sha256.New()
	h.Write(elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y))
	return fmt.Sprintf("locksmith-se-%x", h.Sum(nil)[:8])
}

// SignJWTAssertion creates an RFC 7523 JWT signed with an ECDSA P-256 private key.
func SignJWTAssertion(req ClientAssertionRequest, priv *ecdsa.PrivateKey) (*ClientAssertionResponse, error) {
	if req.Audience == "" {
		return nil, errors.New("assertion: audience is required")
	}
	if req.Subject == "" {
		return nil, errors.New("assertion: subject is required")
	}
	if priv == nil {
		return nil, errors.New("assertion: private key is nil")
	}

	validity := req.Validity
	if validity <= 0 {
		validity = DefaultValidity
	}
	if validity > MaxValidity {
		return nil, fmt.Errorf("assertion: validity %v exceeds maximum permitted %v", validity, MaxValidity)
	}

	now := time.Now().UTC()
	exp := now.Add(validity)

	nonce := req.Nonce
	if nonce == "" {
		randomBytes := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
			return nil, fmt.Errorf("assertion: failed to generate nonce: %w", err)
		}
		nonce = base64URLEncode(randomBytes)
	}

	kid := ComputeKeyID(&priv.PublicKey)

	// 1. Build Header
	header := JWTHeader{
		Alg: "ES256",
		Typ: "JWT",
		Kid: kid,
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("assertion: failed to marshal header: %w", err)
	}

	// 2. Build Claims
	claimsMap := make(map[string]any)
	for k, v := range req.Claims {
		claimsMap[k] = v
	}
	claimsMap["iss"] = req.Subject
	claimsMap["sub"] = req.Subject
	claimsMap["aud"] = req.Audience
	claimsMap["jti"] = nonce
	claimsMap["iat"] = now.Unix()
	claimsMap["nbf"] = now.Unix()
	claimsMap["exp"] = exp.Unix()

	claimsBytes, err := json.Marshal(claimsMap)
	if err != nil {
		return nil, fmt.Errorf("assertion: failed to marshal claims: %w", err)
	}

	// 3. Assemble Signing Input: base64URL(header) + "." + base64URL(claims)
	signingInput := base64URLEncode(headerBytes) + "." + base64URLEncode(claimsBytes)

	// 4. Compute SHA-256 digest
	digest := sha256.Sum256([]byte(signingInput))

	// 5. Sign with ECDSA P-256 (RFC 7515 specifies IEEE P1363 raw r||s format for ES256)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, fmt.Errorf("assertion: ECDSA signing failed: %w", err)
	}

	// Format r and s as 32-byte zero-padded big-endian integers
	sigBytes := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)

	token := signingInput + "." + base64URLEncode(sigBytes)

	return &ClientAssertionResponse{
		AssertionType:  AssertionTypeJWTBearer,
		AssertionToken: token,
		ExpiresAt:      exp,
		KeyID:          kid,
		Algorithm:      "ES256",
	}, nil
}

// VerifyJWTAssertion validates the signature, audience, and expiration of a client assertion.
func VerifyJWTAssertion(tokenStr string, pub *ecdsa.PublicKey, expectedAud string) (map[string]any, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("assertion: invalid JWT structure (expected 3 parts)")
	}

	claimsBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("assertion: failed to decode claims: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("assertion: invalid claims JSON: %w", err)
	}

	// Validate Expiration
	expVal, ok := claims["exp"]
	if !ok {
		return nil, errors.New("assertion: missing exp claim")
	}
	expFloat, ok := expVal.(float64)
	if !ok {
		return nil, errors.New("assertion: exp claim is not numeric")
	}
	if time.Now().UTC().Unix() > int64(expFloat) {
		return nil, errors.New("assertion: token has expired")
	}

	// Validate Audience
	if expectedAud != "" {
		audVal, ok := claims["aud"]
		if !ok || audVal != expectedAud {
			return nil, fmt.Errorf("assertion: audience mismatch (expected %q, got %v)", expectedAud, audVal)
		}
	}

	// Verify Signature
	sigBytes, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("assertion: failed to decode signature: %w", err)
	}
	if len(sigBytes) != 64 {
		return nil, fmt.Errorf("assertion: invalid ES256 signature length %d (expected 64)", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))

	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, errors.New("assertion: cryptographic signature verification failed")
	}

	return claims, nil
}

// WebAuthnAssertion represents a synthesized FIDO2/WebAuthn assertion.
type WebAuthnAssertion struct {
	ClientDataJSON    string `json:"client_data_json"`
	AuthenticatorData string `json:"authenticator_data"`
	Signature         string `json:"signature"`
	KeyID             string `json:"kid"`
}

// SynthesizeWebAuthnAssertion synthesizes a standards-compliant WebAuthn assertion.
func SynthesizeWebAuthnAssertion(req ClientAssertionRequest, priv *ecdsa.PrivateKey) (*ClientAssertionResponse, error) {
	if req.Audience == "" {
		return nil, errors.New("webauthn: audience (RP ID) is required")
	}
	if priv == nil {
		return nil, errors.New("webauthn: private key is nil")
	}

	validity := req.Validity
	if validity <= 0 {
		validity = DefaultValidity
	}

	now := time.Now().UTC()
	exp := now.Add(validity)

	// 1. ClientDataJSON
	clientData := map[string]any{
		"type":        "webauthn.get",
		"challenge":   req.Nonce,
		"origin":      req.Audience,
		"crossOrigin": false,
	}
	clientDataBytes, err := json.Marshal(clientData)
	if err != nil {
		return nil, fmt.Errorf("webauthn: marshal clientData failed: %w", err)
	}

	// 2. AuthenticatorData: 32-byte RP ID hash + 1-byte flags + 4-byte counter
	rpIDHash := sha256.Sum256([]byte(req.Audience))
	authData := make([]byte, 37)
	copy(authData[:32], rpIDHash[:])
	authData[32] = 0x01 // Flags: User Present (UP) set
	binary.BigEndian.PutUint32(authData[33:37], 1) // Signature counter = 1

	// 3. Digest = SHA-256(authData || SHA-256(clientDataJSON))
	clientDataHash := sha256.Sum256(clientDataBytes)
	h := sha256.New()
	h.Write(authData)
	h.Write(clientDataHash[:])
	authDigest := h.Sum(nil)

	// 4. Sign with P-256
	r, s, err := ecdsa.Sign(rand.Reader, priv, authDigest)
	if err != nil {
		return nil, fmt.Errorf("webauthn: signing failed: %w", err)
	}

	sigBytes := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)

	kid := ComputeKeyID(&priv.PublicKey)

	assertionPayload := WebAuthnAssertion{
		ClientDataJSON:    base64URLEncode(clientDataBytes),
		AuthenticatorData: base64URLEncode(authData),
		Signature:         base64URLEncode(sigBytes),
		KeyID:             kid,
	}

	assertionJSON, err := json.Marshal(assertionPayload)
	if err != nil {
		return nil, fmt.Errorf("webauthn: marshal assertion failed: %w", err)
	}

	return &ClientAssertionResponse{
		AssertionType:  AssertionTypeWebAuthn,
		AssertionToken: string(assertionJSON),
		ExpiresAt:      exp,
		KeyID:          kid,
		Algorithm:      "ES256",
	}, nil
}

// SessionAmortizer allows N=8 parallel subagents to derive independent assertion keys
// in memory using HKDF-SHA256 from a single initial hardware Touch ID authorization.
type SessionAmortizer struct {
	mu           sync.RWMutex
	masterSecret []byte
	expiresAt    time.Time
}

// NewSessionAmortizer creates an amortizer from a hardware-authenticated master secret.
func NewSessionAmortizer(masterSecret []byte, validity time.Duration) *SessionAmortizer {
	return &SessionAmortizer{
		masterSecret: append([]byte(nil), masterSecret...),
		expiresAt:    time.Now().UTC().Add(validity),
	}
}

// DeriveSubagentKey derives an isolated ECDSA P-256 private key for a child subagent.
func (a *SessionAmortizer) DeriveSubagentKey(subagentID string) (*ecdsa.PrivateKey, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if time.Now().UTC().After(a.expiresAt) {
		return nil, errors.New("assertion: master biometric session ticket has expired")
	}

	// Deterministic key derivation via HKDF-SHA256
	info := []byte("locksmith.assertion.subagent.key." + subagentID)
	hkdfReader := hkdf.New(sha256.New, a.masterSecret, nil, info)

	// Derive 32-byte scalar D for P-256
	dBytes := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, dBytes); err != nil {
		return nil, fmt.Errorf("assertion: HKDF key derivation failed: %w", err)
	}

	curve := elliptic.P256()
	d := new(big.Int).SetBytes(dBytes)

	// Ensure d < N and d > 0
	d.Mod(d, curve.Params().N)
	if d.Sign() == 0 {
		d.SetInt64(1)
	}

	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = d
	priv.X, priv.Y = curve.ScalarBaseMult(d.Bytes())

	return priv, nil
}
