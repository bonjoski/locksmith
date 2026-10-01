package locksmith

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	masterKeySalt = "sh.locksmith.masterkey.v2"
)

// zeroKey zeroes out a sensitive key slice in memory after use.
func zeroKey(k []byte) {
	for i := range k {
		k[i] = 0
	}
}

// deriveMasterKey derives the primary 32-byte AES-GCM encryption key bound to
// both the machine hardware ID and the current OS user identity.
func deriveMasterKey() ([]byte, error) {
	machineID, err := getMachineID()
	if err != nil {
		return nil, fmt.Errorf("failed to get machine id: %w", err)
	}

	userIdentity, err := CurrentUserIdentity()
	if err != nil {
		return nil, fmt.Errorf("failed to get user identity: %w", err)
	}

	return DeriveKeyWithHKDF(machineID, userIdentity)
}

// deriveLegacyMasterKey derives the legacy 32-byte master key which was derived
// exclusively from the machine hardware ID without user identity binding.
func deriveLegacyMasterKey() ([]byte, error) {
	machineID, err := getMachineID()
	if err != nil {
		return nil, fmt.Errorf("failed to get machine id: %w", err)
	}

	hash := sha256.Sum256([]byte(machineID))
	key := make([]byte, 32)
	copy(key, hash[:])
	return key, nil
}

// DeriveKeyWithHKDF derives a 32-byte AES key bound to both machineID and userIdentity using HKDF-SHA256.
func DeriveKeyWithHKDF(machineID string, user UserIdentity) ([]byte, error) {
	if machineID == "" {
		return nil, fmt.Errorf("machine ID cannot be empty")
	}
	info := fmt.Sprintf("locksmith:cache:v2:uid=%s:user=%s:home=%s", user.UID, user.Username, user.HomeDir)
	kdf := hkdf.New(sha256.New, []byte(machineID), []byte(masterKeySalt), []byte(info))
	key := make([]byte, 32)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("failed to derive key using HKDF: %w", err)
	}
	return key, nil
}
