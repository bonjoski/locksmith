# Locksmith Setup & Development Guide

This guide ensures your environment is correctly configured for developing and running `locksmith`, particularly for features requiring biometric keychain access.

## Prerequisites

- macOS with Touch ID support (or a compatible secure enclave).
- Go (latest version).
- Xcode and Command Line Tools installed.
- An Apple Developer account (Personal Team is sufficient).

## 1. Apple Developer Identity

To use biometric features, the binary MUST be signed with an Apple Developer certificate.

1.  **Create Certificate**: In Xcode > Settings > Accounts, click **Manage Certificates...** and add an **Apple Development** certificate.
2.  **Verify Identity**: Run the following to see your valid identities:
    ```bash
    security find-identity -v -p codesigning
    ```
    You should see an identity like `Apple Development: your@email.com (TEAM_ID)`.

## 2. Trusting the Developer Certificate

When you sign a binary for the first time on a new machine, macOS may block it until you trust the certificate.

1.  Open **Keychain Access**.
2.  Search for your "Apple Development" certificate.
3.  Double-click it, expand the **Trust** section, and set **When using this certificate** to **Always Trust**.
    > [!NOTE]
    > You may only need to do this if macOS doesn't trust it automatically.

## 3. Building and Signing

For Personal Team development of a CLI tool, you MUST sign the binary with your identity. However, you should **avoid** using a separate `entitlements.plist` file, as it can cause signature violations (`Killed: 9`) on standalone binaries.

The `locksmith` code handles biometric authentication manually via `LAContext`, so it does not require explicit keychain access group entitlements.

```bash
# Build the binary
go build -o locksmith ./cmd/locksmith
```

### GPG Commit Signing
This repository is configured to require signed commits.
- **Key ID**: `E5B6FFD7E5EE90FB`
- **Configuration**:
  ```bash
  git config user.signingkey E5B6FFD7E5EE90FB
  git config commit.gpgsign true
  ```

### Development with Biometrics
```bash
# Sign the binary (using your Apple Development identity)
codesign --force --identifier "com.locksmith" --sign "Apple Development" locksmith
```

## 4. Troubleshooting

### "Killed: 9"
This is a code signing violation.
- **Cause**: Usually caused by using an `entitlements.plist` that macOS rejects for standalone binaries.
- **Fix**: Re-sign with JUST the identity and identifier (no `--entitlements` flag).

### "errSecMissingEntitlement" (-34018)
- **Cause**: The binary is not signed or the identity is not trusted.
- **Fix**: Run the `codesign` command above and ensure your certificate is trusted in Keychain Access.

### "Unable to build chain to self-signed root"
If `codesign` fails with this:
1.  Open **Keychain Access** and search for **"Apple Worldwide Developer Relations"**.
2.  Ensure it is set to **"Use System Defaults"** (NOT "Always Trust").
3.  Do the same for your **"Apple Development"** certificate.

## 5. Verifying Signature

To verify the binary is correctly signed:

```bash
# Verify signature details
codesign -dvvv locksmith
```

## 6. Windows Setup

Windows support uses the native **Windows Credential Manager** and **Windows Hello**.

### Prerequisites
- Windows 10 or 11.
- A functional Windows Hello method (PIN, Fingerprint, or Face).
- Go 1.25.4.

### Building on Windows
```powershell
go build -o locksmith.exe ./cmd/locksmith
```

### Biometric Authentication
Windows Hello is handled natively via the `winhello-go` library. Unlike macOS, Windows doesn't require explicit code signing for a CLI tool to access the biometric APIs during local development, but it is recommended for distribution.
