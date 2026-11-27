package redact

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"sync"
)

// TokenMap holds the bi-directional mapping between scrubbed placeholder references
// (e.g. "[SECRET_REF_e7a9b1c2d3e4f501]") and the original raw secret values.
// Raw secrets are stored exclusively in mutable []byte buffers (with HMAC-indexed
// deduplication keys) so Zeroize() overwrites secret bytes in place on the heap.
type TokenMap struct {
	mu           sync.RWMutex
	hmacKey      [32]byte
	refToSecret  map[string][]byte
	digestToRef  map[[32]byte]string
	namedSecrets map[string]string
}

// NewTokenMap initializes an empty thread-safe TokenMap.
func NewTokenMap() *TokenMap {
	tm := &TokenMap{
		refToSecret:  make(map[string][]byte),
		digestToRef:  make(map[[32]byte]string),
		namedSecrets: make(map[string]string),
	}
	if _, err := rand.Read(tm.hmacKey[:]); err != nil {
		panic("redact: crypto/rand failed: " + err.Error())
	}
	return tm
}

func (tm *TokenMap) computeDigest(secret []byte) [32]byte {
	mac := hmac.New(sha256.New, tm.hmacKey[:])
	if _, err := mac.Write(secret); err != nil {
		panic("redact: hmac write failed: " + err.Error())
	}
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// Add inserts a raw secret, returning its consistent placeholder reference.
// If the secret already exists in the map, its existing reference is returned.
func (tm *TokenMap) Add(secret string, optionalName string) string {
	return tm.AddBytes([]byte(secret), optionalName)
}

// AddBytes inserts raw secret bytes into an owned mutable buffer inside TokenMap,
// returning its consistent placeholder reference across the lifetime of the TokenMap.
func (tm *TokenMap) AddBytes(secret []byte, optionalName string) string {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	digest := tm.computeDigest(secret)
	if ref, exists := tm.digestToRef[digest]; exists {
		if existing, ok := tm.refToSecret[ref]; ok && bytes.Equal(existing, secret) {
			if optionalName != "" {
				tm.namedSecrets[optionalName] = ref
			}
			return ref
		}
	}

	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("redact: crypto/rand failed: " + err.Error())
	}
	ref := fmt.Sprintf("[SECRET_REF_%s]", hex.EncodeToString(b))

	owned := make([]byte, len(secret))
	copy(owned, secret)

	tm.refToSecret[ref] = owned
	tm.digestToRef[digest] = ref
	if optionalName != "" {
		tm.namedSecrets[optionalName] = ref
	}

	return ref
}

// GetSecret resolves a placeholder reference back to a string copy of the original secret.
func (tm *TokenMap) GetSecret(ref string) (string, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	secret, ok := tm.refToSecret[ref]
	if !ok {
		return "", false
	}
	return string(secret), true
}

// GetSecretBytes returns a caller-owned copy of the raw secret bytes for a placeholder reference.
func (tm *TokenMap) GetSecretBytes(ref string) ([]byte, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	secret, ok := tm.refToSecret[ref]
	if !ok {
		return nil, false
	}
	out := make([]byte, len(secret))
	copy(out, secret)
	return out, true
}

// GetRef returns the placeholder reference for a known secret value.
func (tm *TokenMap) GetRef(secret string) (string, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	digest := tm.computeDigest([]byte(secret))
	ref, ok := tm.digestToRef[digest]
	if !ok {
		return "", false
	}
	if existing, exists := tm.refToSecret[ref]; !exists || !bytes.Equal(existing, []byte(secret)) {
		return "", false
	}
	return ref, true
}

// Count returns the number of tracked secrets in the map.
func (tm *TokenMap) Count() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return len(tm.refToSecret)
}

// References returns all placeholder tokens in the map.
func (tm *TokenMap) References() []string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	refs := make([]string, 0, len(tm.refToSecret))
	for ref := range tm.refToSecret {
		refs = append(refs, ref)
	}
	return refs
}

// Zeroize overwrites all mutable secret byte slices and HMAC key material in place
// before purging map entries to prevent heap scraping.
func (tm *TokenMap) Zeroize() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	for k, buf := range tm.refToSecret {
		for i := range buf {
			buf[i] = 0
		}
		runtime.KeepAlive(buf)
		delete(tm.refToSecret, k)
	}
	for i := range tm.hmacKey {
		tm.hmacKey[i] = 0
	}
	runtime.KeepAlive(&tm.hmacKey)

	clear(tm.digestToRef)
	clear(tm.namedSecrets)
}
