# Strict Cryptographic Envelope Verification

> **Mitigated Advisory:** `GHSA-j282-pjg5-j643` (Keystore Digest Stripping & Trailing Garbage Injection)  
> **Package:** `github.com/bonjoski/locksmith/v2/pkg/crypto`  
> **Specification:** [`RFC-2026-11-19-42`](https://github.com/bonjoski/spanreed/blob/main/docs/plans/accepted/2026-11-19-mcp-repo-confinement-and-keystore-frame-integrity-rfc.md)

---

## 1. Problem Statement & Threat Scenario

In serialized cryptographic key envelopes, decoders that fail to enforce strict EOF boundaries and exact digest widths allow adversaries to append trailing unauthenticated bytes or truncate authenticating MAC bytes. When decoded, unverified trailing bytes can corrupt parser state or enable length extension attacks.

---

## 2. Invariants & Guarantees

1. **Exact Frame Boundaries:** `len(raw) == 4 + payloadLen + ExpectedMACSize`. Any trailing bytes immediately trigger `ErrTrailingData`.
2. **Constant-Time Comparison:** MAC verification utilizes `subtle.ConstantTimeCompare`, preventing side-channel timing leaks.
3. **Fail-Closed Memory Hygiene:** On integrity failure or corrupted headers, memory slices are rejected and discarded.

---

## 3. Go Usage Recipe

```go
package main

import (
	"fmt"
	"log"

	"github.com/bonjoski/locksmith/v2/pkg/crypto"
)

func main() {
	key := []byte("32-byte-master-authentication-key")
	payload := []byte("database-master-password")

	// 1. Encode into authenticated binary frame
	frame, err := crypto.EncodeFrame(payload, key)
	if err != nil {
		log.Fatalf("encode failed: %v", err)
	}

	// 2. Decode and assert strict frame integrity
	plaintext, err := crypto.VerifyAndDecodeFrame(frame, key)
	if err != nil {
		log.Fatalf("integrity verification failed: %v", err)
	}

	fmt.Printf("Decoded secret: %s\n", string(plaintext))
}
```
