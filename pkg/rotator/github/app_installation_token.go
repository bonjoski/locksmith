package githubrotator

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/rotator"
	"golang.org/x/crypto/ssh"
)

const GitHubAppInstallationTokenRotatorID = "github-app-installation-token"

type AppInstallationTokenRotator struct{}

type appTokenAuthInputs struct {
	jwtIssuer      string
	installationID string
	privateKeyPEM  string
}

func NewAppInstallationTokenRotator() *AppInstallationTokenRotator {
	return &AppInstallationTokenRotator{}
}

func (h *AppInstallationTokenRotator) ID() string {
	return GitHubAppInstallationTokenRotatorID
}

func (h *AppInstallationTokenRotator) Supports(selector rotator.RotationSelector) bool {
	if !strings.EqualFold(strings.TrimSpace(selector.OwnerApplication), "github") {
		return false
	}
	t := strings.ToLower(strings.TrimSpace(selector.SecretType))
	return t == "api_key" || t == "token"
}

func (h *AppInstallationTokenRotator) Rotate(ctx context.Context, input rotator.RotationInput) (rotator.RotationOutput, error) {
	auth, err := loadAppTokenAuthInputs(input.Selector)
	if err != nil {
		return rotator.RotationOutput{}, err
	}

	jwtToken, err := buildGitHubJWTFromPEM(auth.jwtIssuer, auth.privateKeyPEM)
	if err != nil {
		return rotator.RotationOutput{}, err
	}

	client := &http.Client{Timeout: input.Timeout}
	installationID := auth.installationID
	if installationID == "" {
		installationID, err = discoverInstallationID(ctx, client, jwtToken, input.Selector.SourceURL, input.Selector.Metadata)
		if err != nil {
			return rotator.RotationOutput{}, err
		}
	}

	endpoint := installationTokenEndpoint(input.Selector.SourceURL, installationID)
	return requestInstallationToken(ctx, client, jwtToken, endpoint)
}

func loadAppTokenAuthInputs(selector rotator.RotationSelector) (appTokenAuthInputs, error) {
	jwtIssuer := firstNonEmpty(
		readMeta(selector.Metadata, "github_app_client_id"),
		readMeta(selector.Metadata, "app_client_id"),
		readMeta(selector.Metadata, "github_client_id"),
		readMeta(selector.Metadata, "client_id"),
		readMeta(selector.Metadata, "github_app_id"),
		readMeta(selector.Metadata, "app_id"),
		os.Getenv("GITHUB_APP_CLIENT_ID"),
		os.Getenv("GITHUB_CLIENT_ID"),
		os.Getenv("GITHUB_APP_ID"),
	)
	if jwtIssuer == "" {
		return appTokenAuthInputs{}, fmt.Errorf("github app client_id (preferred) or app_id is required (metadata/env)")
	}

	privateKeyPEM := firstNonEmpty(
		readMeta(selector.Metadata, "github_app_private_key"),
		readMeta(selector.Metadata, "app_private_key"),
		os.Getenv("GITHUB_APP_PRIVATE_KEY"),
	)
	if privateKeyPEM == "" {
		return appTokenAuthInputs{}, fmt.Errorf("github app private key is required (metadata.github_app_private_key or GITHUB_APP_PRIVATE_KEY)")
	}

	installationID := firstNonEmpty(
		readMeta(selector.Metadata, "github_installation_id"),
		readMeta(selector.Metadata, "installation_id"),
		installationIDFromEndpoint(selector.SourceURL),
		os.Getenv("GITHUB_APP_INSTALLATION_ID"),
	)

	return appTokenAuthInputs{jwtIssuer: jwtIssuer, installationID: installationID, privateKeyPEM: privateKeyPEM}, nil
}

func buildGitHubJWTFromPEM(jwtIssuer string, privateKeyPEM string) (string, error) {
	privateKey, err := parseRSAPrivateKey([]byte(privateKeyPEM))
	if err != nil {
		return "", fmt.Errorf("failed to parse github app private key: %w", err)
	}

	jwtToken, err := buildGitHubAppJWT(jwtIssuer, privateKey, time.Now().UTC())
	if err != nil {
		return "", fmt.Errorf("failed to build github app jwt: %w", err)
	}

	return jwtToken, nil
}

func installationTokenEndpoint(sourceURL string, installationID string) string {
	endpoint := strings.TrimSpace(sourceURL)
	if endpoint == "" || installationIDFromEndpoint(endpoint) == "" {
		return fmt.Sprintf("%s/app/installations/%s/access_tokens", githubAPIBaseFromSource(endpoint), installationID)
	}
	return endpoint
}

func requestInstallationToken(ctx context.Context, client *http.Client, jwtToken string, endpoint string) (rotator.RotationOutput, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return rotator.RotationOutput{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", defaultGitHubAPIVersion)
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	resp, err := client.Do(req)
	if err != nil {
		return rotator.RotationOutput{}, fmt.Errorf("github app installation token request failed: %w", err)
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

	if resp.StatusCode != http.StatusCreated {
		return rotator.RotationOutput{}, fmt.Errorf("github app installation token request failed with status %d", resp.StatusCode)
	}

	var result struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return rotator.RotationOutput{}, fmt.Errorf("failed to decode github app installation token response: %w", err)
	}

	if strings.TrimSpace(result.Token) == "" {
		return rotator.RotationOutput{}, fmt.Errorf("github app installation token response contained empty token")
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

func discoverInstallationID(ctx context.Context, client *http.Client, jwtToken string, sourceURL string, metadata map[string]string) (string, error) {
	listURL := fmt.Sprintf("%s/app/installations", githubAPIBaseFromSource(sourceURL))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", defaultGitHubAPIVersion)
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("github app installations lookup failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github app installations lookup failed with status %d", resp.StatusCode)
	}

	var installations []struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
		} `json:"account"`
	}
	if err := json.Unmarshal(body, &installations); err != nil {
		return "", fmt.Errorf("failed to decode github app installations response: %w", err)
	}

	if len(installations) == 0 {
		return "", fmt.Errorf("no installations found for github app")
	}

	if len(installations) == 1 {
		return fmt.Sprintf("%d", installations[0].ID), nil
	}

	account := firstNonEmpty(
		readMeta(metadata, "github_installation_account"),
		readMeta(metadata, "installation_account"),
		os.Getenv("GITHUB_APP_INSTALLATION_ACCOUNT"),
	)
	if account != "" {
		for _, inst := range installations {
			if strings.EqualFold(strings.TrimSpace(inst.Account.Login), strings.TrimSpace(account)) {
				return fmt.Sprintf("%d", inst.ID), nil
			}
		}
		return "", fmt.Errorf("no github app installation matched account '%s'", account)
	}

	return "", fmt.Errorf("multiple github app installations found; set metadata.github_installation_id or metadata.github_installation_account")
}

func githubAPIBaseFromSource(source string) string {
	s := strings.TrimSpace(source)
	if s == "" {
		return "https://api.github.com"
	}

	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "https://api.github.com"
	}

	path := strings.TrimRight(u.Path, "/")
	if idx := strings.Index(path, "/app/installations/"); idx >= 0 {
		path = path[:idx]
	}

	base := u.Scheme + "://" + u.Host + strings.TrimRight(path, "/")
	return strings.TrimRight(base, "/")
}

func installationIDFromEndpoint(endpoint string) string {
	s := strings.TrimSpace(endpoint)
	if s == "" {
		return ""
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(strings.TrimSpace(s), "https://"), "/"), "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "app" && parts[i+1] == "installations" {
			return parts[i+2]
		}
	}
	return ""
}

func buildGitHubAppJWT(jwtIssuer string, privateKey *rsa.PrivateKey, now time.Time) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	payload := map[string]any{
		"iat": now.Unix() - 60,
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": strings.TrimSpace(jwtIssuer),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := encodedHeader + "." + encodedPayload

	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	key, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key data: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not rsa")
	}

	return rsaKey, nil
}
