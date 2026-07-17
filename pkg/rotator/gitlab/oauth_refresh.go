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

const OAuthRefreshRotatorID = "gitlab-oauth-refresh"

type OAuthRefreshRotator struct{}

func NewOAuthRefreshRotator() *OAuthRefreshRotator {
	return &OAuthRefreshRotator{}
}

func (h *OAuthRefreshRotator) ID() string {
	return OAuthRefreshRotatorID
}

func (h *OAuthRefreshRotator) Supports(selector rotator.RotationSelector) bool {
	if selector.OwnerApplication != "" && !strings.EqualFold(selector.OwnerApplication, "gitlab") {
		return false
	}

	if selector.SecretType == "" {
		return true
	}

	t := strings.ToLower(strings.TrimSpace(selector.SecretType))
	return t == "oauth_token"
}

func (h *OAuthRefreshRotator) Rotate(ctx context.Context, input rotator.RotationInput) (rotator.RotationOutput, error) {
	refreshToken := firstNonEmpty(
		readMeta(input.Selector.Metadata, "gitlab_refresh_token"),
		readMeta(input.Selector.Metadata, "oauth2_refresh_token"),
		readMeta(input.Selector.Metadata, "refresh_token"),
		os.Getenv("GITLAB_REFRESH_TOKEN"),
	)
	if refreshToken == "" {
		return rotator.RotationOutput{}, fmt.Errorf("gitlab refresh token is required (metadata.gitlab_refresh_token or GITLAB_REFRESH_TOKEN)")
	}

	clientID := firstNonEmpty(
		readMeta(input.Selector.Metadata, "gitlab_client_id"),
		readMeta(input.Selector.Metadata, "client_id"),
		os.Getenv("GITLAB_CLIENT_ID"),
	)
	clientSecret := firstNonEmpty(
		readMeta(input.Selector.Metadata, "gitlab_client_secret"),
		readMeta(input.Selector.Metadata, "client_secret"),
		os.Getenv("GITLAB_CLIENT_SECRET"),
	)

	endpoint, err := resolveOAuthRefreshEndpoint(firstNonEmpty(
		strings.TrimSpace(input.Selector.SourceURL),
		readMeta(input.Selector.Metadata, "gitlab_base_url"),
		os.Getenv("GITLAB_BASE_URL"),
		"https://gitlab.com",
	))
	if err != nil {
		return rotator.RotationOutput{}, err
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	if clientID != "" {
		form.Set("client_id", clientID)
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}

	client := &http.Client{Timeout: input.Timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return rotator.RotationOutput{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return rotator.RotationOutput{}, fmt.Errorf("gitlab oauth refresh request failed: %w", err)
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
		return rotator.RotationOutput{}, fmt.Errorf("gitlab oauth refresh failed with status %d", resp.StatusCode)
	}

	return parseOAuthRefreshResponse(respBytes)
}

func parseOAuthRefreshResponse(respBytes []byte) (rotator.RotationOutput, error) {
	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return rotator.RotationOutput{}, fmt.Errorf("failed to decode gitlab oauth refresh response: %w", err)
	}
	if strings.TrimSpace(result.AccessToken) == "" {
		return rotator.RotationOutput{}, fmt.Errorf("gitlab oauth refresh returned empty access_token")
	}

	var ttl time.Duration
	if result.ExpiresIn > 0 {
		ttl = time.Duration(result.ExpiresIn) * time.Second
	}

	return rotator.RotationOutput{NewValue: []byte(result.AccessToken), TTL: ttl}, nil
}

func resolveOAuthRefreshEndpoint(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid gitlab oauth endpoint: %w", err)
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid gitlab oauth endpoint host")
	}

	cleanPath := path.Clean("/" + strings.TrimSpace(u.Path))
	if cleanPath == "/oauth/token" || strings.HasSuffix(cleanPath, "/oauth/token") {
		u.Path = cleanPath
		return u.String(), nil
	}

	if strings.Contains(cleanPath, "/api/v4") {
		u.Path = "/oauth/token"
		return u.String(), nil
	}

	u.Path = path.Join(cleanPath, "/oauth/token")
	return u.String(), nil
}
