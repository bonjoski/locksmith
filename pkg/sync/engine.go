package sync

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/locksmith"
)

// SyncSecret matches the target serialization schema
type SyncSecret struct {
	Value     []byte    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SyncPayload holds the serialized vault content
type SyncPayload struct {
	Secrets    map[string]SyncSecret `json:"secrets"`
	ExportedAt time.Time             `json:"exported_at"`
}

// ExportVault retrieves all secrets and packs them into a JSON payload
func ExportVault(ls *locksmith.Locksmith) ([]byte, error) {
	keys, err := ls.ListWithMetadata()
	if err != nil {
		return nil, fmt.Errorf("failed to list vault keys: %w", err)
	}

	payload := SyncPayload{
		Secrets:    make(map[string]SyncSecret),
		ExportedAt: time.Now(),
	}

	for key := range keys {
		secret, err := ls.GetWithMetadata(key)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve secret metadata for key '%s': %w", key, err)
		}

		payload.Secrets[key] = SyncSecret{
			Value:     secret.Value,
			CreatedAt: secret.CreatedAt,
			ExpiresAt: secret.ExpiresAt,
		}
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sync payload: %w", err)
	}

	return data, nil
}

// ImportVault merges a decrypted sync payload into the local vault
func ImportVault(ls *locksmith.Locksmith, data []byte, policy string) (int, error) {
	var payload SyncPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return 0, fmt.Errorf("failed to unmarshal sync payload: %w", err)
	}

	importedCount := 0

	for key, impSec := range payload.Secrets {
		localSec, err := ls.GetWithMetadata(key)

		// If secret doesn't exist locally, we always import it
		if err != nil || localSec == nil {
			err = ls.ImportSecret(key, locksmith.Secret{
				Value:     impSec.Value,
				CreatedAt: impSec.CreatedAt,
				ExpiresAt: impSec.ExpiresAt,
			}, ls.Options.RequireBiometrics)
			if err != nil {
				return importedCount, fmt.Errorf("failed to import secret '%s': %w", key, err)
			}
			importedCount++
			continue
		}

		// Conflict resolution based on policy
		shouldUpdate := false
		switch policy {
		case "overwrite":
			shouldUpdate = true
		case "keep-local":
			shouldUpdate = false
		case "latest-wins", "":
			if impSec.CreatedAt.After(localSec.CreatedAt) {
				shouldUpdate = true
			}
		default:
			return importedCount, fmt.Errorf("unknown conflict resolution policy: %s", policy)
		}

		if shouldUpdate {
			err = ls.ImportSecret(key, locksmith.Secret{
				Value:     impSec.Value,
				CreatedAt: impSec.CreatedAt,
				ExpiresAt: impSec.ExpiresAt,
			}, ls.Options.RequireBiometrics)
			if err != nil {
				return importedCount, fmt.Errorf("failed to update secret '%s': %w", key, err)
			}
			importedCount++
		}
	}

	return importedCount, nil
}
