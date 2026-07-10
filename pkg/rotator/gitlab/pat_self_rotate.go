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
	req, err := buildPATSelfRotateRequest(ctx, endpoint, string(input.CurrentValue), input.Selector.Metadata, input.DesiredTTL)
	if err != nil {
		return rotator.RotationOutput{}, err
	}

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

	return parsePATSelfRotateResponse(respBytes)
}

func buildPATSelfRotateRequest(ctx context.Context, endpoint string, currentToken string, metadata map[string]string, desiredTTL time.Duration) (*http.Request, error) {
	expiresAt := firstNonEmpty(
		readMeta(metadata, "gitlab_expires_at"),
		readMeta(metadata, "expires_at"),
		os.Getenv("GITLAB_PAT_EXPIRES_AT"),
	)
	if expiresAt == "" {
		expiresAt = expiresAtFromDesiredTTL(desiredTTL)
	}

	requestBody, err := buildExpiresAtBody(expiresAt)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, requestBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", currentToken)
	req.Header.Set("Accept", "application/json")
	if expiresAt != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	return req, nil
}

func buildExpiresAtBody(expiresAt string) (io.Reader, error) {
	if expiresAt == "" {
		return nil, nil
	}
	if _, err := time.Parse("2006-01-02", expiresAt); err != nil {
		return nil, fmt.Errorf("invalid expires_at '%s': expected YYYY-MM-DD", expiresAt)
	}
	form := url.Values{}
	form.Set("expires_at", expiresAt)
	return strings.NewReader(form.Encode()), nil
}

func parsePATSelfRotateResponse(respBytes []byte) (rotator.RotationOutput, error) {

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

func expiresAtFromDesiredTTL(desiredTTL time.Duration) string {
	if desiredTTL <= 0 {
		return ""
	}
	return time.Now().UTC().Add(desiredTTL).Format("2006-01-02")
}
