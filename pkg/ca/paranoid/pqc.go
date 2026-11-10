package paranoid

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"
)

const (
	// MLDSA65PublicKeySize is the exact NIST FIPS 204 public key length (rho + t1)
	MLDSA65PublicKeySize = 1952
	// MLDSA65PrivateKeySize is the exact NIST FIPS 204 expanded private key length
	MLDSA65PrivateKeySize = 4032
	// MLDSA65SeedSize is the NIST FIPS 204 private key seed length (xi)
	MLDSA65SeedSize = 32
)

// CheckMLDSA65PublicKey validates that a raw ML-DSA-65 public key adheres strictly
// to NIST FIPS 204 byte length and structural non-triviality invariants.
func CheckMLDSA65PublicKey(rawKey []byte) error {
	if len(rawKey) != MLDSA65PublicKeySize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidMLDSALength, MLDSA65PublicKeySize, len(rawKey))
	}

	if isAllZero(rawKey) || isTrivialPattern(rawKey) {
		return fmt.Errorf("%w: public key vector is zeroed or trivial", ErrCryptographicAnomaly)
	}

	return nil
}

// CheckMLDSA65PrivateKey validates that an ML-DSA-65 private key adheres strictly
// to NIST FIPS 204, supporting either the canonical 32-byte seed or the 4032-byte expanded format.
func CheckMLDSA65PrivateKey(rawKey []byte) error {
	if len(rawKey) != MLDSA65SeedSize && len(rawKey) != MLDSA65PrivateKeySize {
		return fmt.Errorf("%w: expected %d (seed) or %d (expanded) bytes, got %d", ErrInvalidMLDSALength, MLDSA65SeedSize, MLDSA65PrivateKeySize, len(rawKey))
	}

	if isAllZero(rawKey) || isTrivialPattern(rawKey) {
		return fmt.Errorf("%w: private key vector is zeroed or trivial", ErrCryptographicAnomaly)
	}

	return nil
}

// CheckMLDSA65SPKI parses an X.509 SubjectPublicKeyInfo structure containing an ML-DSA-65 key
// and validates the enclosed public key bits.
func CheckMLDSA65SPKI(spkiBytes []byte) error {
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spkiBytes, &spki); err != nil {
		// If raw DER isn't standard SPKI, check if bytes themselves are raw key
		if len(spkiBytes) == MLDSA65PublicKeySize {
			return CheckMLDSA65PublicKey(spkiBytes)
		}
		return errors.Join(ErrInvalidMLDSALength, err)
	}

	rawKey := spki.PublicKey.RightAlign()
	if len(rawKey) != MLDSA65PublicKeySize {
		return fmt.Errorf("%w: SPKI bit string is %d bytes, expected %d", ErrInvalidMLDSALength, len(rawKey), MLDSA65PublicKeySize)
	}

	return CheckMLDSA65PublicKey(rawKey)
}

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func isTrivialPattern(b []byte) bool {
	if len(b) < 16 {
		return false
	}
	first := b[0]
	allSame := true
	for _, v := range b {
		if v != first {
			allSame = false
			break
		}
	}
	if allSame {
		return true
	}

	// Check 0x01, 0x02, 0x03 incremental fill
	isIncremental := true
	for i := 1; i < len(b); i++ {
		if b[i] != b[i-1]+1 {
			isIncremental = false
			break
		}
	}
	if isIncremental {
		return true
	}

	// Check repeating 4-byte pattern across entire key
	pattern := b[:4]
	if bytes.Equal(bytes.Repeat(pattern, len(b)/4), b[:(len(b)/4)*4]) {
		return true
	}

	return false
}
