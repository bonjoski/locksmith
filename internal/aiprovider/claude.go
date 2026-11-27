package aiprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type ClaudeProvider struct {
	apiKey        string
	model         string
	httpClient    *http.Client
	baseURL       string
	allowLoopback bool
}

func NewClaudeProvider(apiKey string, model string) *ClaudeProvider {
	if model == "" {
		model = "claude-3-5-sonnet-20241022"
	}
	return &ClaudeProvider{
		apiKey:     apiKey,
		model:      model,
		httpClient: NewSafeHTTPClient(60*time.Second, false),
		baseURL:    "https://api.anthropic.com/v1",
	}
}

func (c *ClaudeProvider) Name() string {
	return "anthropic-claude"
}

type claudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type claudeRequest struct {
	Model       string          `json:"model"`
	MaxTokens   int             `json:"max_tokens"`
	System      string          `json:"system,omitempty"`
	Messages    []claudeMessage `json:"messages"`
	Temperature float64         `json:"temperature,omitempty"`
}

type claudeContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type claudeResponse struct {
	ID         string               `json:"id"`
	Type       string               `json:"type"`
	Role       string               `json:"role"`
	Content    []claudeContentBlock `json:"content"`
	StopReason string               `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *ClaudeProvider) buildClaudeRequest(req Request) (string, string, []byte, error) {
	if c.apiKey == "" {
		return "", "", nil, fmt.Errorf("%w: ANTHROPIC_API_KEY is not configured", ErrProviderFailed)
	}
	model := req.Model
	if model == "" || model == "auto" {
		model = c.model
	}
	if err := ValidateModelName(model); err != nil {
		return "", "", nil, fmt.Errorf("%w: %w", ErrProviderFailed, err)
	}
	cleanBase, err := ValidateBaseURL(c.baseURL, c.allowLoopback, !c.allowLoopback)
	if err != nil {
		return "", "", nil, fmt.Errorf("%w: %w", ErrProviderFailed, err)
	}
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}
	cReq := claudeRequest{
		Model:       model,
		MaxTokens:   maxTokens,
		System:      req.SystemPrompt,
		Temperature: req.Temperature,
		Messages:    make([]claudeMessage, 0, len(req.Messages)),
	}
	for _, msg := range req.Messages {
		if msg.Role == RoleSystem {
			cReq.System = msg.Content
			continue
		}
		cReq.Messages = append(cReq.Messages, claudeMessage{Role: msg.Role, Content: msg.Content})
	}
	bodyBytes, err := json.Marshal(cReq)
	if err != nil {
		return "", "", nil, fmt.Errorf("claude marshal error: %w", err)
	}
	return model, cleanBase, bodyBytes, nil
}

func decodeClaudeResponse(respBytes []byte, model string) (*Response, error) {
	var cResp claudeResponse
	if err := json.Unmarshal(respBytes, &cResp); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidResponse, err)
	}
	if cResp.Error != nil {
		return nil, fmt.Errorf("%w: API error (%s): %s", ErrProviderFailed, cResp.Error.Type, cResp.Error.Message)
	}
	var texts []string
	for _, block := range cResp.Content {
		if block.Type == "text" {
			texts = append(texts, block.Text)
		}
	}
	return &Response{
		Content:      strings.Join(texts, "\n"),
		Model:        model,
		FinishReason: cResp.StopReason,
		Usage: TokenUsage{
			InputTokens:  cResp.Usage.InputTokens,
			OutputTokens: cResp.Usage.OutputTokens,
		},
	}, nil
}

func (c *ClaudeProvider) Complete(ctx context.Context, req Request) (resp *Response, err error) {
	model, cleanBase, bodyBytes, err := c.buildClaudeRequest(req)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/messages", cleanBase)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("claude request creation failed: %w", sanitizeTransportError(err))
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProviderFailed, sanitizeTransportError(err))
	}
	defer func() {
		if closeErr := httpResp.Body.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	respBytes, err := ReadBoundedBody(httpResp.Body, MaxUpstreamResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("claude read response failed: %w", err)
	}
	return decodeClaudeResponse(respBytes, model)
}
