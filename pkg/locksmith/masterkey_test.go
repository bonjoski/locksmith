package locksmith

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCurrentUserIdentity(t *testing.T) {
	identity, err := CurrentUserIdentity()
	if err != nil {
		t.Fatalf("CurrentUserIdentity failed: %v", err)
	}

	if identity.UID == "" && identity.Username == "" {
		t.Errorf("Expected at least UID or Username to be non-empty, got %+v", identity)
	}
}

func TestDeriveKeyWithHKDF_Deterministic(t *testing.T) {
	user := UserIdentity{
		UID:      "501",
		Username: "alice",
		HomeDir:  "/Users/alice",
	}
	machineID := "machine-uuid-12345"

	key1, err := DeriveKeyWithHKDF(machineID, user)
	if err != nil {
		t.Fatalf("DeriveKeyWithHKDF failed: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("Expected 32-byte key, got %d bytes", len(key1))
	}

	key2, err := DeriveKeyWithHKDF(machineID, user)
	if err != nil {
		t.Fatalf("DeriveKeyWithHKDF failed on second call: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Errorf("Expected deterministic key derivation, but key1 != key2")
	}
}

func TestDeriveKeyWithHKDF_UniquenessAcrossUsers(t *testing.T) {
	machineID := "shared-workstation-uuid"

	userAlice := UserIdentity{
		UID:      "1001",
		Username: "alice",
		HomeDir:  "/home/alice",
	}

	userBob := UserIdentity{
		UID:      "1002",
		Username: "bob",
		HomeDir:  "/home/bob",
	}

	keyAlice, err := DeriveKeyWithHKDF(machineID, userAlice)
	if err != nil {
		t.Fatalf("Failed to derive key for Alice: %v", err)
	}

	keyBob, err := DeriveKeyWithHKDF(machineID, userBob)
	if err != nil {
		t.Fatalf("Failed to derive key for Bob: %v", err)
	}

	// Defense in depth: keys must differ on the same machine
	if bytes.Equal(keyAlice, keyBob) {
		t.Fatalf("Security failure: Alice and Bob on same machine derived identical keys!")
	}

	// Difference when only UID changes
	userAliceDifferentUID := userAlice
	userAliceDifferentUID.UID = "9999"
	keyDifferentUID, _ := DeriveKeyWithHKDF(machineID, userAliceDifferentUID)
	if bytes.Equal(keyAlice, keyDifferentUID) {
		t.Errorf("Expected different key when UID changes")
	}

	// Difference when only Username changes
	userAliceDifferentName := userAlice
	userAliceDifferentName.Username = "alice2"
	keyDifferentName, _ := DeriveKeyWithHKDF(machineID, userAliceDifferentName)
	if bytes.Equal(keyAlice, keyDifferentName) {
		t.Errorf("Expected different key when Username changes")
	}

	// Difference when only HomeDir changes
	userAliceDifferentHome := userAlice
	userAliceDifferentHome.HomeDir = "/home/other"
	keyDifferentHome, _ := DeriveKeyWithHKDF(machineID, userAliceDifferentHome)
	if bytes.Equal(keyAlice, keyDifferentHome) {
		t.Errorf("Expected different key when HomeDir changes")
	}

	// Difference when machine ID changes
	keyDifferentMachine, _ := DeriveKeyWithHKDF("different-machine-uuid", userAlice)
	if bytes.Equal(keyAlice, keyDifferentMachine) {
		t.Errorf("Expected different key when MachineID changes")
	}
}

func TestDeriveKeyWithHKDF_EmptyMachineID(t *testing.T) {
	user := UserIdentity{UID: "501", Username: "alice"}
	_, err := DeriveKeyWithHKDF("", user)
	if err == nil {
		t.Error("Expected error when machineID is empty, got nil")
	}
}

func TestDeriveMasterKey_DiffersFromLegacy(t *testing.T) {
	masterKey, err := deriveMasterKey()
	if err != nil {
		t.Fatalf("deriveMasterKey failed: %v", err)
	}
	if len(masterKey) != 32 {
		t.Fatalf("Expected 32-byte master key, got %d", len(masterKey))
	}

	legacyKey, err := deriveLegacyMasterKey()
	if err != nil {
		t.Fatalf("deriveLegacyMasterKey failed: %v", err)
	}
	if len(legacyKey) != 32 {
		t.Fatalf("Expected 32-byte legacy key, got %d", len(legacyKey))
	}

	if bytes.Equal(masterKey, legacyKey) {
		t.Errorf("Expected user-bound master key to differ from legacy machine-only key")
	}
}

func TestDiskCache_DefenseInDepthUserIsolation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "locksmith-test-cache-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	machineID := "host-system-id-1234"
	userA := UserIdentity{UID: "501", Username: "alice", HomeDir: tempDir}
	userB := UserIdentity{UID: "502", Username: "bob", HomeDir: tempDir}

	keyA, err := DeriveKeyWithHKDF(machineID, userA)
	if err != nil {
		t.Fatalf("Failed to derive key A: %v", err)
	}
	keyB, err := DeriveKeyWithHKDF(machineID, userB)
	if err != nil {
		t.Fatalf("Failed to derive key B: %v", err)
	}

	cacheA := &DiskCache{Dir: tempDir, MasterKey: keyA}
	cacheB := &DiskCache{Dir: tempDir, MasterKey: keyB}

	secretKey := "isolated-secret"
	secretVal := Secret{
		Value:     []byte("confidential-payload-for-user-a"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// User A saves secret
	if err := cacheA.Set(secretKey, secretVal, time.Hour); err != nil {
		t.Fatalf("User A failed to save secret: %v", err)
	}

	// Verify User A can decrypt
	readA, err := cacheA.Get(secretKey)
	if err != nil || readA == nil || !bytes.Equal(readA.Value, secretVal.Value) {
		t.Fatalf("User A failed to read own secret: %v", err)
	}

	// Defense in depth verification: User B reading User A's file MUST fail decryption
	readB, err := cacheB.Get(secretKey)
	if err == nil {
		t.Fatalf("Security failure! User B was able to decrypt User A's cached secret: %v", readB)
	}
}

func TestDiskCache_TransparentAutoMigration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "locksmith-migration-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	machineID := "test-workstation-id"
	legacyKey, err := deriveLegacyMasterKey()
	if err != nil {
		t.Fatalf("deriveLegacyMasterKey failed: %v", err)
	}

	userA := UserIdentity{UID: "501", Username: "alice", HomeDir: tempDir}
	userKey, err := DeriveKeyWithHKDF(machineID, userA)
	if err != nil {
		t.Fatalf("DeriveKeyWithHKDF failed: %v", err)
	}

	// 1. Create a legacy cache and write an item using legacy key
	legacyCache := &DiskCache{Dir: tempDir, MasterKey: legacyKey}
	cacheItemKey := "legacy-cached-credential"
	secretData := Secret{
		Value:      []byte("super-secret-legacy-token"),
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(1 * time.Hour),
		SecretType: "oauth",
	}

	if err := legacyCache.Set(cacheItemKey, secretData, time.Hour); err != nil {
		t.Fatalf("Failed to write legacy cache item: %v", err)
	}

	// 2. Initialize new cache with primary UserKey and LegacyKey
	migratingCache := &DiskCache{
		Dir:             tempDir,
		MasterKey:       userKey,
		LegacyMasterKey: legacyKey,
	}

	// 3. First read should succeed transparently and re-encrypt the file
	retrieved, err := migratingCache.Get(cacheItemKey)
	if err != nil {
		t.Fatalf("Failed to read legacy cache item with migrating cache: %v", err)
	}
	if retrieved == nil || !bytes.Equal(retrieved.Value, secretData.Value) {
		t.Fatalf("Retrieved secret mismatch: expected %s, got %v", secretData.Value, retrieved)
	}

	// 4. Verify that the file on disk is NOW encrypted with the new userKey
	// A cache that only has the userKey (no legacy key) should now be able to read it!
	userOnlyCache := &DiskCache{
		Dir:       tempDir,
		MasterKey: userKey,
	}
	fromMigrated, err := userOnlyCache.Get(cacheItemKey)
	if err != nil || fromMigrated == nil {
		t.Fatalf("Migrated file could not be decrypted by userOnlyCache: %v", err)
	}
	if !bytes.Equal(fromMigrated.Value, secretData.Value) {
		t.Errorf("Migrated value mismatch: expected %s, got %s", secretData.Value, fromMigrated.Value)
	}

	// 5. A cache that only has the legacyKey should now FAIL to decrypt the migrated file
	legacyOnlyCache := &DiskCache{
		Dir:       tempDir,
		MasterKey: legacyKey,
	}
	_, err = legacyOnlyCache.Get(cacheItemKey)
	if err == nil {
		t.Errorf("Expected legacyOnlyCache to FAIL decrypting migrated file, but it succeeded!")
	}
}

func TestDiskCache_CorruptedCacheFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "locksmith-corrupt-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	mockKey := make([]byte, 32)
	cache := &DiskCache{Dir: tempDir, MasterKey: mockKey}

	// Write garbage ciphertext
	corruptPath := filepath.Join(tempDir, "corrupt-file")
	if err := os.WriteFile(corruptPath, []byte("too-short"), 0600); err != nil {
		t.Fatalf("Failed to write corrupt file: %v", err)
	}

	_, err = cache.Get("corrupt-file")
	if err == nil {
		t.Error("Expected error for corrupt/too-short cache file, got nil")
	}

	// Write invalid JSON ciphertext
	secretBytes := []byte("plain text not json")
	enc, err := cache.encrypt(secretBytes)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if err := os.WriteFile(corruptPath, enc, 0600); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	var s Secret
	if err := json.Unmarshal(secretBytes, &s); err == nil {
		t.Fatal("expected unmarshal error")
	}
	_, err = cache.Get("corrupt-file")
	if err == nil {
		t.Error("Expected error unmarshaling invalid secret json, got nil")
	}
}
