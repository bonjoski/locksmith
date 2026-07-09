package githubrotator

import (
	"bytes"
	"context"
	"encoding/base64"
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

const OAuthResetRotatorID = "github-oauth-reset"
const defaultGitHubAPIVersion = "2022-11-28"

type OAuthResetRotator struct{}

func NewOAuthResetRotator() *OAuthResetRotator {
	return &OAuthResetRotator{}
}

func (h *OAuthResetRotator) ID() string {
	return OAuthResetRotatorID
}

func (h *OAuthResetRotator) Supports(selector rotator.RotationSelector) bool {
	if !strings.EqualFold(selector.SecretType, "oauth_token") {
		return false
	}
	if selector.OwnerApplication == "" {
		return true
	}
	return strings.EqualFold(selector.OwnerApplication, "github")
}

func (h *OAuthResetRotator) Rotate(ctx context.Context, input rotator.RotationInput) (rotator.RotationOutput, error) {
	if len(input.CurrentValue) == 0 {
		return rotator.RotationOutput{}, fmt.Errorf("current OAuth token is required")
	}

	clientID, clientSecret, err := loadOAuthClientCredentials(input.Selector)
	if err != nil {
		return rotator.RotationOutput{}, err
	}

	endpoint := oauthResetEndpoint(input.Selector.SourceURL, clientID)
	payload, err := oauthResetPayload(input.CurrentValue)
	if err != nil {
		return rotator.RotationOutput{}, err
	}

	respBytes, status, err := doOAuthResetRequest(ctx, input.Timeout, endpoint, clientID, clientSecret, payload)
	if err != nil {
		return rotator.RotationOutput{}, err
	}
	defer func() {
		for i := range respBytes {
			respBytes[i] = 0
		}
	}()

	if status != http.StatusOK {
		return rotator.RotationOutput{}, fmt.Errorf("github oauth token reset failed with status %d", status)
	}

	return parseOAuthResetResponse(respBytes)
}

func loadOAuthClientCredentials(selector rotator.RotationSelector) (string, string, error) {
	clientID := firstNonEmpty(
		readMeta(selector.Metadata, "github_client_id"),
		readMeta(selector.Metadata, "client_id"),
		clientIDFromGitHubEndpoint(selector.SourceURL),
		os.Getenv("GITHUB_CLIENT_ID"),
	)
	if clientID == "" {
		return "", "", fmt.Errorf("github client_id is required (metadata.github_client_id, source_url path, or GITHUB_CLIENT_ID)")
	}

	clientSecret := firstNonEmpty(
		readMeta(selector.Metadata, "github_client_secret"),
		readMeta(selector.Metadata, "client_secret"),
		os.Getenv("GITHUB_CLIENT_SECRET"),
	)
	if clientSecret == "" {
		return "", "", fmt.Errorf("github client_secret is required (metadata.github_client_secret or GITHUB_CLIENT_SECRET)")
	}

	return clientID, clientSecret, nil
}

func oauthResetEndpoint(sourceURL string, clientID string) string {
	endpoint := strings.TrimSpace(sourceURL)
	if endpoint == "" {
		return fmt.Sprintf("https://api.github.com/applications/%s/token", clientID)
	}
	return endpoint
}

func oauthResetPayload(currentValue []byte) ([]byte, error) {
	return json.Marshal(map[string]string{"access_token": string(currentValue)})
}

func doOAuthResetRequest(ctx context.Context, timeout time.Duration, endpoint string, clientID string, clientSecret string, payload []byte) ([]byte, int, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", defaultGitHubAPIVersion)
	req.Header.Set("Authorization", basicAuthHeader(clientID, clientSecret))

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("github oauth token reset request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	return respBytes, resp.StatusCode, nil
}

func parseOAuthResetResponse(respBytes []byte) (rotator.RotationOutput, error) {
	var result struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return rotator.RotationOutput{}, fmt.Errorf("failed to decode github oauth token reset response: %w", err)
	}

	if strings.TrimSpace(result.Token) == "" {
		return rotator.RotationOutput{}, fmt.Errorf("github oauth token reset returned empty token")
	}

	var ttl time.Duration
	if strings.TrimSpace(result.ExpiresAt) != "" {
		if exp, err := time.Parse(time.RFC3339, result.ExpiresAt); err == nil {
			ttl = time.Until(exp)
			if ttl < 0 {
				ttl = 0
			}
		}
	}

	return rotator.RotationOutput{NewValue: []byte(result.Token), TTL: ttl}, nil
}

func clientIDFromGitHubEndpoint(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	parts := strings.Split(path.Clean(u.Path), "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "applications" && parts[i+2] == "token" {
			return parts[i+1]
		}
	}
	return ""
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

func basicAuthHeader(user string, pass string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	return "Basic " + encoded
}
