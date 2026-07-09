package githubrotator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/rotator"
)

const FGPATReplaceRotatorID = "github-fgpat-replace"

type FGPATReplaceRotator struct{}

func NewFGPATReplaceRotator() *FGPATReplaceRotator {
	return &FGPATReplaceRotator{}
}

func (h *FGPATReplaceRotator) ID() string {
	return FGPATReplaceRotatorID
}

func (h *FGPATReplaceRotator) Supports(selector rotator.RotationSelector) bool {
	if !strings.EqualFold(selector.OwnerApplication, "github") {
		return false
	}
	t := strings.ToLower(strings.TrimSpace(selector.SecretType))
	return t == "api_key" || t == "token"
}

func (h *FGPATReplaceRotator) Rotate(ctx context.Context, input rotator.RotationInput) (rotator.RotationOutput, error) {
	if len(input.CurrentValue) == 0 {
		return rotator.RotationOutput{}, fmt.Errorf("current GitHub fine-grained personal access token is required")
	}

	endpoint := fgpatReplaceEndpoint(input.Selector)
	if endpoint == "" {
		return rotator.RotationOutput{}, fmt.Errorf("github fine-grained PAT replace endpoint is required (source_url, metadata, or GITHUB_FGPAT_REPLACE_URL)")
	}

	payload, err := fgpatReplacePayload(input)
	if err != nil {
		return rotator.RotationOutput{}, err
	}

	respBytes, status, err := postFGPATReplace(ctx, input.Timeout, endpoint, payload)
	if err != nil {
		return rotator.RotationOutput{}, err
	}
	defer func() {
		for i := range respBytes {
			respBytes[i] = 0
		}
	}()

	if status != http.StatusOK && status != http.StatusCreated {
		return rotator.RotationOutput{}, fmt.Errorf("github fine-grained PAT replace failed with status %d", status)
	}

	return parseFGPATReplaceResponse(respBytes)
}

func fgpatReplaceEndpoint(selector rotator.RotationSelector) string {
	return firstNonEmpty(
		strings.TrimSpace(selector.SourceURL),
		readMeta(selector.Metadata, "github_fgpat_replace_url"),
		readMeta(selector.Metadata, "replace_url"),
		readMeta(selector.Metadata, "broker_url"),
		os.Getenv("GITHUB_FGPAT_REPLACE_URL"),
	)
}

func fgpatReplacePayload(input rotator.RotationInput) ([]byte, error) {
	return json.Marshal(map[string]string{
		"key":           input.Key,
		"action":        "replace",
		"provider":      "github",
		"token_kind":    "fine_grained_pat",
		"current_token": string(input.CurrentValue),
	})
}

func postFGPATReplace(ctx context.Context, timeout time.Duration, endpoint string, payload []byte) ([]byte, int, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("github fine-grained PAT replace request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	return respBytes, resp.StatusCode, nil
}

func parseFGPATReplaceResponse(respBytes []byte) (rotator.RotationOutput, error) {

	var result struct {
		Token     string `json:"token"`
		Value     string `json:"value"`
		ExpiresIn string `json:"expires_in"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return rotator.RotationOutput{}, fmt.Errorf("failed to decode github fine-grained PAT replace response: %w", err)
	}

	newToken := firstNonEmpty(result.Token, result.Value)
	if newToken == "" {
		return rotator.RotationOutput{}, fmt.Errorf("github fine-grained PAT replace returned empty token")
	}

	var ttl time.Duration
	if strings.TrimSpace(result.ExpiresIn) != "" {
		if d, err := parseDurationWithCalendarUnits(result.ExpiresIn); err == nil {
			ttl = d
		}
	}
	if ttl == 0 && strings.TrimSpace(result.ExpiresAt) != "" {
		if exp, err := time.Parse(time.RFC3339, result.ExpiresAt); err == nil {
			ttl = time.Until(exp)
			if ttl < 0 {
				ttl = 0
			}
		}
	}

	return rotator.RotationOutput{NewValue: []byte(newToken), TTL: ttl}, nil
}

func parseDurationWithCalendarUnits(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid duration: %s", s)
	}
	if strings.HasSuffix(s, "mo") {
		var months int
		if _, err := fmt.Sscanf(strings.TrimSuffix(s, "mo"), "%d", &months); err != nil {
			return 0, err
		}
		return time.Duration(months) * 30 * 24 * time.Hour, nil
	}
	last := s[len(s)-1]
	var n int
	if _, err := fmt.Sscanf(s[:len(s)-1], "%d", &n); err != nil {
		return 0, err
	}
	switch last {
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	case 'w':
		return time.Duration(n) * 7 * 24 * time.Hour, nil
	case 'y':
		return time.Duration(n) * 365 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("invalid duration format: %s", s)
	}
}
