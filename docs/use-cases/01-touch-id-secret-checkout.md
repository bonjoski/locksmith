# Recipe: Biometric Touch ID Secrets Checkout

> **Use Case ID:** `LCK-UC-01`  
> **Target Audience:** Developers, CLI Power Users, SecOps  
> **Platform Engine:** macOS Secure Enclave & Touch ID / Windows Hello  

---

## 1. Problem Statement

Developers frequently need access to high-value secrets (production database passwords, OpenAI/Anthropic API keys, cloud tokens) from the command line. Storing these in plaintext shell scripts, `.zshrc`, or unencrypted files exposes them to malware, rogue CLI tools, and accidental git commits.

---

## 2. When to Use This

Use **Touch ID Secrets Checkout** when you want cryptographic hardware protection for sensitive tokens. The secret is encrypted with a key locked in the hardware Secure Enclave. Access requires a physical biometric tap (Touch ID) or Apple Watch confirmation, and the decrypted plaintext is zeroized from memory immediately after use.

---

## 3. Architecture & Dataflow

```mermaid
flowchart LR
    Dev["Developer / CLI: 'locksmith get OPENAI_API_KEY'"] --> Vault["🔐 Locksmith CLI"]
    
    Vault --> Enclave["🍎 macOS Secure Enclave / Touch ID<br/>(Hardware User Presence Verification)"]
    
    Enclave -->|Biometric Match (Fingerprint/Watch)| Decrypt["Decrypt Secret Payload in Memory"]
    
    Decrypt --> Stdout["Print to stdout / pipe to tool"]
    Stdout --> Zeroize["Immediate memclr() memory wipe"]
```

---

## 4. Prerequisites

1. **Locksmith Installed:** `brew install bonjoski/locksmith/locksmith` (ensures code-signing entitlements for Keychain access).
2. **Hardware:** Mac with Touch ID sensor or Apple Watch with "Unlock with Apple Watch" enabled.

---

## 5. Step-by-Step Recipe

### Step 1: Store a Secret in the Biometric Vault
```bash
# Store a secret interactively (prompts securely for value)
locksmith add OPENAI_API_KEY

# Or store directly with value
locksmith add GITHUB_PAT ghp_xxxxxxxxxxxxxxxxxxxx
```

### Step 2: Retrieve the Secret with Biometric Authentication
```bash
# Triggers Touch ID prompt on Mac
locksmith get OPENAI_API_KEY
```
A native macOS modal dialog appears: *"Locksmith wants to access key 'OPENAI_API_KEY'"*. Place your finger on the sensor. The decrypted secret is emitted to stdout.

### Step 3: Pipe Secret Directly to Commands
Never echo or save the key to disk:
```bash
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $(locksmith get OPENAI_API_KEY)"
```

---

## 6. Verification & Expected Output

Verify that the secret was securely stored:
```bash
locksmith list
```
Expected output:
```text
🔐 Stored Secrets in Locksmith Vault:
├── OPENAI_API_KEY   [Hardware Biometric: ACTIVE] (Last Accessed: 2m ago)
└── GITHUB_PAT       [Hardware Biometric: ACTIVE] (Last Accessed: 1d ago)
Total: 2 secrets stored.
```

---

## 7. Security Invariants & Blast Radius

- **Hardware-Enforced Presence:** Keys cannot be extracted programmatically in the background without physical user presence.
- **Fail-Closed on Headless Sessions:** If an SSH session or detached background script attempts to read the secret without user interaction rights, Locksmith fails closed with `errSecInteractionNotAllowed`.
- **In-Memory Fragment Slicing:** Secret bytes are held in fragmented memory buffers and scrubbed using zero-allocation wiping (`memclr`) upon process exit.

---

## 8. Troubleshooting & Common Pitfalls

- **Issue:** Command fails with `User interaction not allowed (errSecInteractionNotAllowed)`.  
  **Remediation:** macOS Keychain requires a desktop window server session for biometric prompts. If running over SSH, unlock the session keychain first:
  ```bash
  security unlock-keychain
  ```
