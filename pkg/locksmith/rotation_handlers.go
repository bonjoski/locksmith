package locksmith

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/rotator"
	githubrotator "github.com/bonjoski/locksmith/v2/pkg/rotator/github"
	gitlabrotator "github.com/bonjoski/locksmith/v2/pkg/rotator/gitlab"
)

const defaultURLRotatorID = "url-json"

func registerDefaultRotationHandlers(l *Locksmith) {
	if l == nil || l.Rotators == nil {
		return
	}
	_ = l.Rotators.Register(githubrotator.NewAppInstallationTokenRotator())
	_ = l.Rotators.Register(githubrotator.NewFGPATReplaceRotator())
	_ = l.Rotators.Register(githubrotator.NewOAuthResetRotator())
	_ = l.Rotators.Register(gitlabrotator.NewPATSelfRotateRotator())
	_ = l.Rotators.Register(&urlJSONRotator{})
}

type urlJSONRotator struct{}

func (h *urlJSONRotator) ID() string {
	return defaultURLRotatorID
}

func (h *urlJSONRotator) Supports(selector rotator.RotationSelector) bool {
	return selector.SourceURL != ""
}

func (h *urlJSONRotator) Rotate(ctx context.Context, input rotator.RotationInput) (rotator.RotationOutput, error) {
	if input.Selector.SourceURL == "" {
		return rotator.RotationOutput{}, fmt.Errorf("source_url is required for url-json rotator")
	}

	client := &http.Client{Timeout: input.Timeout}
	payloadBytes, err := json.Marshal(map[string]string{
		"key":               input.Key,
		"action":            "rotate",
		"secret_type":       input.Selector.SecretType,
		"owner_application": input.Selector.OwnerApplication,
	})
	if err != nil {
		return rotator.RotationOutput{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, input.Selector.SourceURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return rotator.RotationOutput{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return rotator.RotationOutput{}, fmt.Errorf("rotator request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return rotator.RotationOutput{}, fmt.Errorf("rotator returned status %d", resp.StatusCode)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return rotator.RotationOutput{}, err
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
		return rotator.RotationOutput{}, fmt.Errorf("failed to decode rotator response: %w", err)
	}

	if strings.TrimSpace(respData.Value) == "" {
		return rotator.RotationOutput{}, fmt.Errorf("rotator returned empty secret value")
	}

	var ttl time.Duration
	if respData.ExpiresIn != "" {
		if d, err := parseDurationForRotator(respData.ExpiresIn); err == nil {
			ttl = d
		}
	}

	return rotator.RotationOutput{NewValue: []byte(respData.Value), TTL: ttl}, nil
}

func parseDurationForRotator(s string) (time.Duration, error) {
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	return ParseDuration(s)
}
