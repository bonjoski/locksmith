//go:build locksmith_admin

package locksmith

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/rotator"
)

// RotateSecret executes the configured in-process Go rotator for the given key and updates the vault.
func (l *Locksmith) RotateSecret(key string) error {
	currentSecret, err := l.getSecretNoRotate(key)
	if err != nil {
		return fmt.Errorf("failed to load secret '%s' before rotation: %w", key, err)
	}

	matchedRule, selector, err := l.findRotationRule(key, currentSecret)
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

	handler, err := l.resolveRotationHandler(matchedRule, selector)
	if err != nil {
		return err
	}

	selector, err = l.resolveSelectorMetadata(selector)
	if err != nil {
		return err
	}

	result, err := handler.Rotate(ctx, rotator.RotationInput{
		Key:          key,
		CurrentValue: currentSecret.Value,
		Selector:     selector,
		Timeout:      timeout,
	})

	if err != nil {
		return err
	}

	defer func() {
		// Zero out local new value buffer
		for i := range result.NewValue {
			result.NewValue[i] = 0
		}
	}()

	expiresAt := l.calculateRotationExpiration(currentSecret, result.TTL)

	valCopy := make([]byte, len(result.NewValue))
	copy(valCopy, result.NewValue)
	err = l.SetWithContext(
		key,
		valCopy,
		expiresAt,
		l.Options.RequireBiometrics,
		ParseSecretType(selector.SecretType),
		selector.OwnerApplication,
		selector.SourceURL,
		selector.Metadata,
	)
	if err != nil {
		return fmt.Errorf("failed to write rotated secret back to vault: %w", err)
	}

	return nil
}

func (l *Locksmith) findRotationRule(key string, secret *Secret) (*RotationRule, rotator.RotationSelector, error) {
	if l.Config == nil {
		return nil, rotator.RotationSelector{}, fmt.Errorf("no matching rotation rule found for key '%s'", key)
	}
	for _, rule := range l.Config.Rotation {
		matched, err := filepath.Match(rule.Secret, key)
		if err != nil {
			continue // ignore malformed pattern
		}
		if !matched {
			continue
		}

		selector := l.buildRotationSelector(key, secret, &rule)
		if !ruleSupportsSelector(&rule, selector) {
			continue
		}

		r := rule
		return &r, selector, nil
	}
	return nil, rotator.RotationSelector{}, fmt.Errorf("no matching rotation rule found for key '%s'", key)
}

func (l *Locksmith) buildRotationSelector(key string, secret *Secret, rule *RotationRule) rotator.RotationSelector {
	sel := rotator.RotationSelector{Key: key}
	if secret != nil {
		sel.SecretType = string(secret.SecretType)
		sel.OwnerApplication = secret.OwnerApplication
		sel.SourceURL = secret.SourceURL
		sel.Metadata = secret.Metadata
	}
	if sel.SecretType == "" {
		sel.SecretType = string(rule.SecretType)
	}
	if sel.OwnerApplication == "" {
		sel.OwnerApplication = rule.OwnerApplication
	}
	if sel.SourceURL == "" {
		sel.SourceURL = rule.SourceURL
	}
	if sel.Metadata == nil {
		sel.Metadata = make(map[string]string)
	}
	for mk, mv := range rule.Metadata {
		sel.Metadata[mk] = mv
	}
	return sel
}

func (l *Locksmith) resolveSelectorMetadata(selector rotator.RotationSelector) (rotator.RotationSelector, error) {
	if len(selector.Metadata) == 0 {
		return selector, nil
	}

	resolved := make(map[string]string, len(selector.Metadata))
	for k, v := range selector.Metadata {
		resolvedVal, err := l.resolveMetadataValue(v)
		if err != nil {
			return selector, fmt.Errorf("failed to resolve metadata '%s': %w", k, err)
		}
		resolved[k] = resolvedVal
	}
	selector.Metadata = resolved
	return selector, nil
}

func (l *Locksmith) resolveMetadataValue(v string) (string, error) {
	s := strings.TrimSpace(v)
	if !strings.HasPrefix(s, "locksmith://") {
		return v, nil
	}

	secretKey := strings.TrimPrefix(s, "locksmith://")
	secretKey = strings.TrimSpace(secretKey)
	if secretKey == "" {
		return "", fmt.Errorf("empty locksmith metadata reference")
	}

	sec, err := l.getSecretNoRotate(secretKey)
	if err != nil {
		return "", fmt.Errorf("unable to load referenced secret '%s': %w", secretKey, err)
	}

	return string(sec.Value), nil
}

func ruleSupportsSelector(rule *RotationRule, selector rotator.RotationSelector) bool {
	if rule.SecretType != SecretTypeUnspecified && selector.SecretType != string(rule.SecretType) {
		return false
	}
	if rule.OwnerApplication != "" && selector.OwnerApplication != rule.OwnerApplication {
		return false
	}
	if rule.SourceURL != "" && selector.SourceURL != rule.SourceURL {
		return false
	}
	return true
}

func (l *Locksmith) resolveRotationHandler(rule *RotationRule, selector rotator.RotationSelector) (rotator.Handler, error) {
	if rule.HookType != "" || rule.HookTarget != "" {
		return nil, fmt.Errorf("legacy hook_type/hook_target is no longer supported; use rotator and source_url")
	}
	if l.Rotators == nil {
		return nil, fmt.Errorf("no rotator registry configured")
	}

	if rule.Rotator != "" {
		h, ok := l.Rotators.ResolveByID(rule.Rotator)
		if !ok {
			return nil, fmt.Errorf("no rotator registered with id '%s'", rule.Rotator)
		}
		if !h.Supports(selector) {
			return nil, fmt.Errorf("rotator '%s' does not support selector for key '%s'", rule.Rotator, selector.Key)
		}
		return h, nil
	}

	h, ok := l.Rotators.Resolve(selector)
	if !ok {
		return nil, fmt.Errorf("no compatible rotator found for key '%s' (type='%s', owner='%s', source_url='%s')", selector.Key, selector.SecretType, selector.OwnerApplication, selector.SourceURL)
	}

	return h, nil
}

func (l *Locksmith) calculateRotationExpiration(existing *Secret, newTTL time.Duration) time.Time {
	expiresAt := time.Now().Add(30 * 24 * time.Hour) // default 30 days
	if newTTL > 0 {
		return time.Now().Add(newTTL)
	}

	if existing != nil {
		originalTTL := existing.ExpiresAt.Sub(existing.CreatedAt)
		if originalTTL > 0 {
			expiresAt = time.Now().Add(originalTTL)
		}
	}

	return expiresAt
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

	threshold := 10 * 24 * time.Hour // default fallback
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
