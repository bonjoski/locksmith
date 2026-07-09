package gitlabrotator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/rotator"
)

const PATSelfRotateRotatorID = "gitlab-pat-self-rotate"
const patSelfRotatePath = "/api/v4/personal_access_tokens/self/rotate"

type PATSelfRotateRotator struct{}

func NewPATSelfRotateRotator() *PATSelfRotateRotator {
	return &PATSelfRotateRotator{}
}

func (h *PATSelfRotateRotator) ID() string {
	return PATSelfRotateRotatorID
}

func (h *PATSelfRotateRotator) Supports(selector rotator.RotationSelector) bool {
	if selector.OwnerApplication != "" && !strings.EqualFold(selector.OwnerApplication, "gitlab") {
		return false
	}

	if selector.SecretType != "" {
		t := strings.ToLower(strings.TrimSpace(selector.SecretType))
		if t != "api_key" && t != "token" && t != "oauth_token" {
			return false
		}
	}

	if selector.OwnerApplication == "" && selector.SecretType == "" && strings.TrimSpace(selector.SourceURL) == "" {
		return false
	}

	return true
}

func (h *PATSelfRotateRotator) Rotate(ctx context.Context, input rotator.RotationInput) (rotator.RotationOutput, error) {
	if len(input.CurrentValue) == 0 {
		return rotator.RotationOutput{}, fmt.Errorf("current GitLab personal access token is required")
	}

	base := firstNonEmpty(
		strings.TrimSpace(input.Selector.SourceURL),
		readMeta(input.Selector.Metadata, "gitlab_base_url"),
		os.Getenv("GITLAB_BASE_URL"),
		"https://gitlab.com",
	)

	endpoint, err := resolveSelfRotateEndpoint(base)
	if err != nil {
		return rotator.RotationOutput{}, err
	}

	client := &http.Client{Timeout: input.Timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return rotator.RotationOutput{}, err
	}
	req.Header.Set("PRIVATE-TOKEN", string(input.CurrentValue))
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return rotator.RotationOutput{}, fmt.Errorf("gitlab pat self-rotate request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return rotator.RotationOutput{}, err
	}
	defer func() {
		for i := range respBytes {
			respBytes[i] = 0
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return rotator.RotationOutput{}, fmt.Errorf("gitlab pat self-rotate failed with status %d", resp.StatusCode)
	}

	var result struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return rotator.RotationOutput{}, fmt.Errorf("failed to decode gitlab self-rotate response: %w", err)
	}
	if strings.TrimSpace(result.Token) == "" {
		return rotator.RotationOutput{}, fmt.Errorf("gitlab self-rotate returned empty token")
	}

	var ttl time.Duration
	if strings.TrimSpace(result.ExpiresAt) != "" {
		expiresAtDate, err := time.Parse("2006-01-02", result.ExpiresAt)
		if err == nil {
			endOfDayUTC := expiresAtDate.UTC().Add(24*time.Hour - time.Nanosecond)
			ttl = time.Until(endOfDayUTC)
			if ttl < 0 {
				ttl = 0
			}
		}
	}

	return rotator.RotationOutput{NewValue: []byte(result.Token), TTL: ttl}, nil
}

func resolveSelfRotateEndpoint(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid gitlab endpoint: %w", err)
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid gitlab endpoint host")
	}

	cleanPath := path.Clean("/" + strings.TrimSpace(u.Path))
	if cleanPath == "/personal_access_tokens/self/rotate" || strings.HasSuffix(cleanPath, patSelfRotatePath) {
		u.Path = cleanPath
		return u.String(), nil
	}

	if strings.Contains(cleanPath, "/api/v4") {
		u.Path = path.Join(cleanPath, "personal_access_tokens", "self", "rotate")
		return u.String(), nil
	}

	u.Path = path.Join(cleanPath, patSelfRotatePath)
	return u.String(), nil
}

func readMeta(m map[string]string, key string) string {
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[key])
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
