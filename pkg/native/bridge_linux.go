//go:build linux
// +build linux

package native

import (
	"fmt"
	"os/exec"

	"github.com/zalando/go-keyring"
)

// performAuthPrompt uses pkexec to force an interactive authentication prompt
// This emulates the biometric/interactive requirements from macOS/Windows on Linux.
func performAuthPrompt(prompt string) error {
	if prompt == "" {
		prompt = "Authentication required for Locksmith"
	}

	// pkexec allows an authorized user to execute PROGRAM as another user.
	// If the user is unprivileged, they are asked to authenticate.
	// We just run a dummy echo command to force the prompt.
	cmd := exec.Command("pkexec", "echo", prompt)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	return nil
}

func Set(service, account string, data []byte, requireBiometrics bool) error {
	if requireBiometrics {
		if err := performAuthPrompt("Authentication required to save secret"); err != nil {
			return err
		}
	}

	return keyring.Set(service, account, string(data))
}

func Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	if useBiometrics {
		if err := performAuthPrompt(prompt); err != nil {
			return nil, err
		}
	}

	val, err := keyring.Get(service, account)
	if err != nil {
		if err == keyring.ErrNotFound {
			return nil, fmt.Errorf("Secret not found") // match windows bridge error convention
		}
		return nil, err
	}
	return []byte(val), nil
}

func Delete(service, account string, useBiometrics bool, prompt string) error {
	if useBiometrics {
		if err := performAuthPrompt(prompt); err != nil {
			return err
		}
	}

	err := keyring.Delete(service, account)
	if err != nil && err != keyring.ErrNotFound {
		return err
	}
	return nil
}

func List(service string, useBiometrics bool, prompt string) ([]string, error) {
	if useBiometrics {
		if err := performAuthPrompt(prompt); err != nil {
			return nil, err
		}
	}

	// zalando/go-keyring does not currently have a "List()" function
	// that returns all keys for a service natively.
	// This means we cannot list the keys in the Linux keychain natively through that library yet.
	// For now, we will return an error stating that listing is not supported on Linux yet.
	return nil, fmt.Errorf("listing secrets is not natively supported by the Linux keyring bridge yet")
}
