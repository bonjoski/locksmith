package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
)

var (
	// ErrEnvelopeCorrupt indicates the cryptographic envelope failed length or integrity checks.
	ErrEnvelopeCorrupt = errors.New("envelope: frame corrupt or integrity check failed")

	// ErrTrailingData indicates trailing unauthenticated bytes were found after the payload.
	ErrTrailingData = errors.New("envelope: trailing bytes detected after authenticated frame")

	// ErrTruncatedDigest indicates the digest length does not match the expected width.
	ErrTruncatedDigest = errors.New("envelope: truncated or malformed digest")

	// ErrInvalidKey indicates the HMAC authentication key is empty or invalid.
	ErrInvalidKey = errors.New("envelope: invalid or empty authentication key")
)

const (
	// ExpectedMACSize defines the exact width of a SHA-256 HMAC (32 bytes).
	ExpectedMACSize = 32
)

// AuthenticatedFrame represents a strictly delimited cryptographic envelope.
type AuthenticatedFrame struct {
	Payload []byte
	MAC     [ExpectedMACSize]byte
}

// EncodeFrame serializes a plaintext payload into an authenticated binary frame.
// Framing format:
// [0:4] Payload Length (BigEndian uint32)
// [4:4+len] Payload bytes
// [4+len:4+len+32] HMAC-SHA256(key, Length || Payload)
func EncodeFrame(payload []byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, ErrInvalidKey
	}

	payloadLen := len(payload)
	out := make([]byte, 4+payloadLen+ExpectedMACSize)
	out[0] = byte(payloadLen >> 24)
	out[1] = byte(payloadLen >> 16)
	out[2] = byte(payloadLen >> 8)
	out[3] = byte(payloadLen)

	copy(out[4:], payload)

	mac := hmac.New(sha256.New, key)
	mac.Write(out[:4+payloadLen])
	expectedMAC := mac.Sum(nil)
	copy(out[4+payloadLen:], expectedMAC)

	return out, nil
}

// VerifyAndDecodeFrame validates that a byte slice contains exactly one authenticated frame.
// Enforces strict constant-time MAC comparison, exact frame boundaries, and zero trailing bytes (mitigating GHSA-j282-pjg5-j643).
func VerifyAndDecodeFrame(raw []byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, ErrInvalidKey
	}

	if len(raw) < ExpectedMACSize+4 { // Minimum: 4-byte payload length + 32-byte MAC
		return nil, ErrEnvelopeCorrupt
	}

	// Extract declared payload length (BigEndian uint32)
	payloadLen := int(raw[0])<<24 | int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	if payloadLen < 0 {
		return nil, ErrEnvelopeCorrupt
	}

	expectedTotal := 4 + payloadLen + ExpectedMACSize

	// Enforce exact boundary: no truncated frames, no trailing garbage
	if len(raw) < expectedTotal {
		return nil, ErrEnvelopeCorrupt
	}
	if len(raw) > expectedTotal {
		return nil, ErrTrailingData
	}

	payload := raw[4 : 4+payloadLen]
	receivedMAC := raw[4+payloadLen : expectedTotal]

	// Compute HMAC over declared length prefix + payload
	mac := hmac.New(sha256.New, key)
	mac.Write(raw[:4+payloadLen])
	expectedMAC := mac.Sum(nil)

	if subtle.ConstantTimeCompare(receivedMAC, expectedMAC) != 1 {
		return nil, ErrEnvelopeCorrupt
	}

	// Return defensive copy of plaintext payload
	out := make([]byte, len(payload))
	copy(out, payload)
	return out, nil
}
