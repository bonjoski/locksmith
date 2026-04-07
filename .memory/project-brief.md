# Project Brief: Locksmith 🔐

**Locksmith** is a secure, biometric-protected keychain vault designed for modern developers and DevOps workflows. It provides a standardized interface for managing secrets across macOS, Windows, and Linux, leveraging native hardware-backed security.

## Core Value Proposition

- **Hardware-Backed Security**: Enforces biometric authentication (Touch ID, Windows Hello, Polkit) for accessing sensitive data.
- **Cross-Platform Consistency**: Provides a unified CLI and library interface for secrets, regardless of the underlying OS keychain service.
- **DevOps Integration**: Designed to be used with tools like [Summon](https://cyberark.github.io/summon) to safely inject secrets into containerized environments and scripts without exposing them in plaintext.

## Key Features

- **Biometric Protection**: macOS `LocalAuthentication`, Windows Hello, and Linux Secret Service.
- **Native Storage**: Uses macOS Keychain, Windows Credential Manager, and Linux DBus Secret Service.
- **Expiration Management**: Built-in TTL and notification system for secret rotation.
- **Admin vs. Read-Only**: Fine-grained control over secret modification via Go build tags (`locksmith_admin`).
- **Memory Security**: Immediate zeroing of sensitive data after use to prevent memory scraping.

## Target Audience

- Developers needing a secure way to store local application secrets.
- DevOps engineers looking to automate secret injection using biometric gates on developer machines.
- Security-conscious users who want an alternative to plaintext `.env` files.
