package aiprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type OllamaProvider struct {
	baseURL       string
	model         string
	httpClient    *http.Client
	allowLoopback bool
}

func NewOllamaProvider(baseURL string, model string) *OllamaProvider {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	if model == "" {
		model = "qwen2.5-coder:latest"
	}
	allowLoop := false
	if u, err := url.Parse(baseURL); err == nil && isLiteralLoopbackHost(u.Hostname()) {
		allowLoop = true
	}
	return &OllamaProvider{
		baseURL:       baseURL,
		model:         model,
		allowLoopback: allowLoop,
		httpClient:    NewSafeHTTPClient(120*time.Second, allowLoop),
	}
}

func (o *OllamaProvider) Name() string {
	return "ollama-local"
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
}

type ollamaChatResponse struct {
	Model           string        `json:"model"`
	CreatedAt       string        `json:"created_at"`
	Message         ollamaMessage `json:"message"`
	Done            bool          `json:"done"`
	TotalDuration   int64         `json:"total_duration"`
	PromptEvalCount int           `json:"prompt_eval_count"`
	EvalCount       int           `json:"eval_count"`
}

func (o *OllamaProvider) Complete(ctx context.Context, req Request) (resp *Response, err error) {
	model := req.Model
	if model == "" || model == "auto" {
		model = o.model
	}

	cleanBase, err := ValidateBaseURL(o.baseURL, o.allowLoopback, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProviderFailed, err)
	}

	messages := make([]ollamaMessage, 0, len(req.Messages)+1)
	if req.SystemPrompt != "" {
		messages = append(messages, ollamaMessage{
			Role:    RoleSystem,
			Content: req.SystemPrompt,
		})
	}
	for _, m := range req.Messages {
		messages = append(messages, ollamaMessage{
			Role:    m.Role,
			Content: m.Content,
		})
	}

	olReq := ollamaChatRequest{
		Model:    model,
		Messages: messages,
		Stream:   false,
	}

	bodyBytes, err := json.Marshal(olReq)
	if err != nil {
		return nil, fmt.Errorf("ollama marshal error: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/chat", cleanBase)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("ollama request creation failed: %w", sanitizeTransportError(err))
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := o.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to connect to Ollama daemon: %w", ErrProviderFailed, sanitizeTransportError(err))
	}
	defer func() {
		if closeErr := httpResp.Body.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	respBytes, err := ReadBoundedBody(httpResp.Body, MaxUpstreamResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("ollama read response failed: %w", err)
	}

	var olResp ollamaChatResponse
	if err := json.Unmarshal(respBytes, &olResp); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidResponse, err)
	}

	return &Response{
		Content:      olResp.Message.Content,
		Model:        model,
		FinishReason: "stop",
		Usage: TokenUsage{
			InputTokens:  olResp.PromptEvalCount,
			OutputTokens: olResp.EvalCount,
		},
	}, nil
}
