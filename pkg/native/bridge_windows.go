//go:build windows
// +build windows

package native

import (
	"errors"
	"fmt"

	"github.com/danieljoos/wincred"
	"github.com/julian-bruyers/winhello-go"
)

func Set(service, account string, data []byte, requireBiometrics bool) error {
	if requireBiometrics {
		if !winhello.Available() {
			return errors.New("Windows Hello is not available on this device")
		}

		// Authenticate before saving
		success, err := winhello.Authenticate("Authentication required to save secret")
		if err != nil {
			return fmt.Errorf("Windows Hello authentication failed: %w", err)
		}
		if !success {
			return errors.New("Windows Hello authentication failed")
		}
	}

	cred := wincred.NewGenericCredential(service + ":" + account)
	cred.CredentialBlob = data
	cred.Persist = wincred.PersistLocalMachine

	return cred.Write()
}

func Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	if useBiometrics {
		if !winhello.Available() {
			return nil, errors.New("Windows Hello is not available on this device")
		}

		if prompt == "" {
			prompt = "Authentication required to access secret"
		}
		success, err := winhello.Authenticate(prompt)
		if err != nil {
			return nil, fmt.Errorf("Windows Hello authentication failed: %w", err)
		}
		if !success {
			return nil, errors.New("Windows Hello authentication failed")
		}
	}

	cred, err := wincred.GetGenericCredential(service + ":" + account)
	if err != nil {
		if errors.Is(err, wincred.ErrElementNotFound) {
			return nil, errors.New("Secret not found")
		}
		return nil, err
	}

	return cred.CredentialBlob, nil
}

func Delete(service, account string, useBiometrics bool, prompt string) error {
	if useBiometrics {
		if !winhello.Available() {
			return errors.New("Windows Hello is not available on this device")
		}

		if prompt == "" {
			prompt = "Authentication required to delete secret"
		}
		success, err := winhello.Authenticate(prompt)
		if err != nil {
			return fmt.Errorf("Windows Hello authentication failed: %w", err)
		}
		if !success {
			return errors.New("Windows Hello authentication failed")
		}
	}

	cred, err := wincred.GetGenericCredential(service + ":" + account)
	if err != nil {
		if errors.Is(err, wincred.ErrElementNotFound) {
			return nil // Already deleted
		}
		return err
	}

	return cred.Delete()
}

func List(service string, useBiometrics bool, prompt string) ([]string, error) {
	if useBiometrics {
		if !winhello.Available() {
			return nil, errors.New("Windows Hello is not available on this device")
		}

		if prompt == "" {
			prompt = "Authentication required to list secrets"
		}
		success, err := winhello.Authenticate(prompt)
		if err != nil {
			return nil, fmt.Errorf("Windows Hello authentication failed: %w", err)
		}
		if !success {
			return nil, errors.New("Windows Hello authentication failed")
		}
	}

	creds, err := wincred.List()
	if err != nil {
		return nil, err
	}

	var keys []string
	prefix := service + ":"
	for _, cred := range creds {
		if cred.TargetName != "" && len(cred.TargetName) > len(prefix) && cred.TargetName[:len(prefix)] == prefix {
			keys = append(keys, cred.TargetName[len(prefix):])
		}
	}

	return keys, nil
}
