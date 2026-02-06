// Biometric Drift Detection Implementation Notes
//
// SECURITY CONSIDERATION: Template Poisoning Attack
// If a malicious actor with local admin access adds their fingerprint to the Mac,
// they could potentially access secrets protected by biometrics.
//
// RECOMMENDED MITIGATION:
// Track the LAContext.evaluatedPolicyDomainState hash to detect when biometric
// templates change. This state changes when:
// - A new fingerprint is added
// - A fingerprint is removed
// - Face ID data is modified
//
// IMPLEMENTATION APPROACH:
// 1. After successful biometric authentication, capture:
//    NSData *domainState = [context evaluatedPolicyDomainState];
//
// 2. On first use, store SHA-256 hash of domainState in a secure location
//    (e.g., a separate keychain item or encrypted file)
//
// 3. On subsequent authentications, compare current hash with stored hash
//
// 4. If hashes differ, require additional authentication (e.g., master password)
//    before allowing access to secrets
//
// CURRENT STATUS:
// This is documented for future implementation. The current implementation
// relies on macOS Secure Enclave hardware protection and biometric authentication
// without drift detection.
//
// TRADE-OFFS:
// - Adds complexity to the authentication flow
// - Requires secure storage for the domain state hash
// - May cause false positives if legitimate fingerprints are added
// - Provides defense-in-depth against local privilege escalation attacks
