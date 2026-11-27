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

type OpenAIProvider struct {
	apiKey        string
	model         string
	baseURL       string
	httpClient    *http.Client
	allowLoopback bool
}

func NewOpenAIProvider(apiKey string, model string, baseURL string) *OpenAIProvider {
	if model == "" {
		model = "gpt-4o"
	}
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	return &OpenAIProvider{
		apiKey:     apiKey,
		model:      model,
		baseURL:    baseURL,
		httpClient: NewSafeHTTPClient(60*time.Second, false),
	}
}

func (o *OpenAIProvider) Name() string {
	return "openai-compatible"
}

type openAIChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIChatRequest struct {
	Model       string              `json:"model"`
	Messages    []openAIChatMessage `json:"messages"`
	Temperature float64             `json:"temperature,omitempty"`
}

type openAIChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

func (o *OpenAIProvider) buildOpenAIRequest(req Request) (string, string, []byte, error) {
	model := req.Model
	if model == "" || model == "auto" {
		model = o.model
	}
	if err := ValidateModelName(model); err != nil {
		return "", "", nil, fmt.Errorf("%w: %w", ErrProviderFailed, err)
	}
	cleanBase, err := ValidateBaseURL(o.baseURL, o.allowLoopback, !o.allowLoopback)
	if err != nil {
		return "", "", nil, fmt.Errorf("%w: %w", ErrProviderFailed, err)
	}
	messages := make([]openAIChatMessage, 0, len(req.Messages)+1)
	if req.SystemPrompt != "" {
		messages = append(messages, openAIChatMessage{Role: RoleSystem, Content: req.SystemPrompt})
	}
	for _, m := range req.Messages {
		messages = append(messages, openAIChatMessage{Role: m.Role, Content: m.Content})
	}
	bodyBytes, err := json.Marshal(openAIChatRequest{Model: model, Messages: messages, Temperature: req.Temperature})
	if err != nil {
		return "", "", nil, fmt.Errorf("openai marshal error: %w", err)
	}
	return model, cleanBase, bodyBytes, nil
}

func decodeOpenAIResponse(respBytes []byte, model string) (*Response, error) {
	var oResp openAIChatResponse
	if err := json.Unmarshal(respBytes, &oResp); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidResponse, err)
	}
	if oResp.Error != nil {
		return nil, fmt.Errorf("%w: API error: %s", ErrProviderFailed, oResp.Error.Message)
	}
	if len(oResp.Choices) == 0 {
		return nil, fmt.Errorf("%w: no choices returned", ErrInvalidResponse)
	}
	return &Response{
		Content:      oResp.Choices[0].Message.Content,
		Model:        model,
		FinishReason: oResp.Choices[0].FinishReason,
		Usage: TokenUsage{
			InputTokens:  oResp.Usage.PromptTokens,
			OutputTokens: oResp.Usage.CompletionTokens,
		},
	}, nil
}

func (o *OpenAIProvider) Complete(ctx context.Context, req Request) (resp *Response, err error) {
	model, cleanBase, bodyBytes, err := o.buildOpenAIRequest(req)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/chat/completions", strings.TrimRight(cleanBase, "/"))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("openai request creation failed: %w", sanitizeTransportError(err))
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if o.apiKey != "" {
		httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", o.apiKey))
	}

	httpResp, err := o.httpClient.Do(httpReq)
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
		return nil, fmt.Errorf("openai read response failed: %w", err)
	}
	return decodeOpenAIResponse(respBytes, model)
}
