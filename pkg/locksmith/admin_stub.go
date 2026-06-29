// admin_stub.go - provides stub admin methods when the build tag 'locksmith_admin' is not enabled
package locksmith

import (
	"fmt"
	"time"
)

// SetWithBiometrics stores a secret with an explicit biometric requirement.
// This stub returns an error indicating admin features are unavailable.
func (l *Locksmith) SetWithBiometrics(key string, value []byte, expiresAt time.Time, requireBiometrics bool) error {
    // Zero out the secret value before exiting to avoid lingering plaintext in memory
    defer func() {
        for i := range value {
            value[i] = 0
        }
    }()
    return fmt.Errorf("admin features not enabled; SetWithBiometrics unavailable")
}

// Delete removes a secret, enforcing biometric prompt.
func (l *Locksmith) Delete(key string) error {
    return fmt.Errorf("admin features not enabled; Delete unavailable")
}

// RotateSecret rotates a single secret's expiration.
func (l *Locksmith) RotateSecret(name string, newExpiry string) error {
    return fmt.Errorf("admin features not enabled; RotateSecret unavailable")
}

// RotateExpiringSecrets rotates all secrets that are close to expiry.
func (l *Locksmith) RotateExpiringSecrets() error {
    return fmt.Errorf("admin features not enabled; RotateExpiringSecrets unavailable")
}
