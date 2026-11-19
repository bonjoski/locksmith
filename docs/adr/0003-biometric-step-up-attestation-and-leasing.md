# ADR-0003: Biometric Step-Up Attestation & Touch ID Amortized Leasing

- **Status:** Accepted
- **Date:** 2026-11-04
- **Component:** `pkg/stepup`, `pkg/native`
- **Deciders:** Lead Security Architect & Cryptographic Systems Engineer

---

## 1. Context & Problem Statement

High-risk actions executed by autonomous agents (e.g., git push, production database mutations, cloud IAM edits) require explicit human-in-the-loop elevation.
- Standard sudo / password prompts disrupt automated execution and can be intercepted by keyloggers.
- Popping biometric Touch ID prompts for every subagent tool invocation causes UI freeze and severe prompt fatigue when $N=8$ parallel subagents execute concurrently.

---

## 2. Decision Outcome

We built **Biometric Step-Up Attestation & Amortized Session Leasing** (`locksmith step-up`):

1. **Native Hardware Biometrics:**
   - Wraps macOS `LocalAuthentication` (`LAPolicyDeviceOwnerAuthenticationWithBiometrics`) and Windows Hello `UserConsentVerifier`.
2. **Cryptographic Attestation Token:**
   - On successful biometric verification, Locksmith mints a compact Ed25519-signed attestation token containing challenge digest, severity tier, timestamp, and expiration.
3. **Amortized Session Leasing:**
   - Caches valid biometric assertions in memory under a 5-minute lease window for the authorized session hierarchy, permitting parallel child subagents to execute without prompt storms.

---

## 3. Consequences

- **Positive:** Non-repudiable biometric elevation; prompt fatigue eliminated for parallel multi-agent trees.
- **Negative:** Requires active console session on developer endpoint (fails closed when display is locked).
