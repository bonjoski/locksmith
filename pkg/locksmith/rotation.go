//go:build locksmith_admin

package locksmith

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// RotateSecret executes the configured rotation hook for the given key and updates the vault
func (l *Locksmith) RotateSecret(key string) error {
	matchedRule, err := l.findRotationRule(key)
	if err != nil {
		return err
	}

	// Timeout configuration
	timeout := 30 * time.Second
	if matchedRule.Timeout != "" {
		if d, err := parseDurationFlex(matchedRule.Timeout); err == nil {
			timeout = d
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var newValue []byte
	var newTTL time.Duration

	switch matchedRule.HookType {
	case "script":
		newValue, err = l.executeScriptRotation(ctx, matchedRule, key)
	case "webhook":
		newValue, newTTL, err = l.executeWebhookRotation(ctx, matchedRule, key, timeout)
	default:
		return fmt.Errorf("unsupported rotation hook type: %s", matchedRule.HookType)
	}

	if err != nil {
		return err
	}

	defer func() {
		// Zero out local new value buffer
		for i := range newValue {
			newValue[i] = 0
		}
	}()

	expiresAt := l.calculateRotationExpiration(key, newTTL)

	// Update vault (uses same biometric settings from options)
	// Create a copy so we can safely zero out the local newValue buffer
	valCopy := make([]byte, len(newValue))
	copy(valCopy, newValue)
	err = l.Set(key, valCopy, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to write rotated secret back to vault: %w", err)
	}

	return nil
}

func (l *Locksmith) findRotationRule(key string) (*RotationRule, error) {
	if l.Config == nil {
		return nil, fmt.Errorf("no matching rotation rule found for key '%s'", key)
	}
	for _, rule := range l.Config.Rotation {
		matched, err := filepath.Match(rule.Secret, key)
		if err != nil {
			continue // ignore malformed pattern
		}
		if matched {
			// return pointer to rule copy to avoid returning address of loop variable
			r := rule
			return &r, nil
		}
	}
	return nil, fmt.Errorf("no matching rotation rule found for key '%s'", key)
}

func (l *Locksmith) calculateRotationExpiration(key string, newTTL time.Duration) time.Time {
	expiresAt := time.Now().Add(30 * 24 * time.Hour) // default 30 days
	if newTTL > 0 {
		return time.Now().Add(newTTL)
	}

	if existing, err := l.getSecretNoRotate(key); err == nil && existing != nil {
		originalTTL := existing.ExpiresAt.Sub(existing.CreatedAt)
		if originalTTL > 0 {
			expiresAt = time.Now().Add(originalTTL)
		}
	}

	return expiresAt
}

func (l *Locksmith) executeScriptRotation(ctx context.Context, rule *RotationRule, key string) ([]byte, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/c", rule.HookTarget, key) // #nosec G204 // nosem
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", rule.HookTarget, key) // #nosec G204 // nosem
	}

	cmd.Env = append(os.Environ(),
		fmt.Sprintf("LOCKSMITH_KEY=%s", key),
		"LOCKSMITH_ACTION=rotate",
	)

	var stdoutBytes, stderrBytes bytes.Buffer
	cmd.Stdout = &stdoutBytes
	cmd.Stderr = &stderrBytes

	err := cmd.Run()
	defer func() {
		// Zero out raw stdout buffer
		b := stdoutBytes.Bytes()
		for i := range b {
			b[i] = 0
		}
	}()

	if err != nil {
		return nil, fmt.Errorf("rotation script failed: %w (stderr: %s)", err, strings.TrimSpace(stderrBytes.String()))
	}

	stdoutStr := strings.TrimSpace(stdoutBytes.String())
	if stdoutStr == "" {
		return nil, fmt.Errorf("rotation script returned an empty value")
	}
	return []byte(stdoutStr), nil
}

func (l *Locksmith) executeWebhookRotation(ctx context.Context, rule *RotationRule, key string, timeout time.Duration) ([]byte, time.Duration, error) {
	client := &http.Client{Timeout: timeout}
	payloadBytes, err := json.Marshal(map[string]string{
		"key":    key,
		"action": "rotate",
	})
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", rule.HookTarget, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		for i := range respBytes {
			respBytes[i] = 0
		}
	}()

	var respData struct {
		Value     string `json:"value"`
		ExpiresIn string `json:"expires_in"`
	}
	if err := json.Unmarshal(respBytes, &respData); err != nil {
		return nil, 0, fmt.Errorf("failed to decode webhook response: %w", err)
	}

	if respData.Value == "" {
		return nil, 0, fmt.Errorf("webhook returned empty secret value")
	}

	var newTTL time.Duration
	if respData.ExpiresIn != "" {
		if d, err := parseDurationFlex(respData.ExpiresIn); err == nil {
			newTTL = d
		}
	}

	return []byte(respData.Value), newTTL, nil
}

// AutoRotateIfExpiring triggers rotation if the secret has reached its warning threshold
func (l *Locksmith) AutoRotateIfExpiring(key string) (bool, error) {
	if l.Config == nil {
		return false, nil
	}

	secret, err := l.getSecretNoRotate(key)
	if err != nil || secret == nil {
		return false, nil // Secret doesn't exist
	}

	threshold, err := l.Config.GetExpiringThreshold()
	if err != nil {
		threshold = 7 * 24 * time.Hour // default fallback
	}

	status := secret.GetExpirationStatus(threshold)
	if status == StatusValid {
		return false, nil // Secret is still valid and not expiring
	}

	// Perform rotation
	err = l.RotateSecret(key)
	if err != nil {
		return false, fmt.Errorf("auto-rotation failed for key '%s': %w", key, err)
	}

	return true, nil
}

// checkLazyRotation triggers auto-rotation if the secret is expiring
func (l *Locksmith) checkLazyRotation(key string) {
	_, _ = l.AutoRotateIfExpiring(key)
}

// parseDurationFlex parses standard Go durations and custom locksmith durations (d, w, mo, y)
func parseDurationFlex(s string) (time.Duration, error) {
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	return ParseDuration(s)
}

// RotateExpiringSecrets scans all stored secrets and rotates any that are expiring or expired
func (l *Locksmith) RotateExpiringSecrets() (rotated []string, skipped []string, failed map[string]error, err error) {
	keys, err := l.ListWithMetadata()
	if err != nil {
		return nil, nil, nil, err
	}

	threshold := 7 * 24 * time.Hour // default fallback
	if l.Config != nil {
		if t, err := l.Config.GetExpiringThreshold(); err == nil {
			threshold = t
		}
	}

	failed = make(map[string]error)

	for key := range keys {
		secret, err := l.getSecretNoRotate(key)
		if err != nil {
			continue // skip secrets we can't retrieve (e.g. access denied)
		}

		status := secret.GetExpirationStatus(threshold)
		if status == StatusValid {
			skipped = append(skipped, key)
			continue
		}

		// Check if a rotation rule exists for this key
		hasRule := false
		if l.Config != nil {
			for _, rule := range l.Config.Rotation {
				matched, err := filepath.Match(rule.Secret, key)
				if err == nil && matched {
					hasRule = true
					break
				}
			}
		}

		if !hasRule {
			skipped = append(skipped, key)
			continue
		}

		// Rotate
		err = l.RotateSecret(key)
		if err != nil {
			failed[key] = err
		} else {
			rotated = append(rotated, key)
		}
	}

	return rotated, skipped, failed, nil
}
