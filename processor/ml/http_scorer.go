package ml

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPScorer calls a remote scoring service (typically the Python
// model_server in this repo). Used in production when the model is large
// or trained in Python and we don't want to ship ONNX. Adds ~1-5ms of
// network latency per call vs. an in-process scorer.
type HTTPScorer struct {
	url     string
	client  *http.Client
	timeout time.Duration
}

type HTTPScorerConfig struct {
	URL     string
	Timeout time.Duration
}

func NewHTTPScorer(cfg HTTPScorerConfig) *HTTPScorer {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	return &HTTPScorer{
		url:     cfg.URL,
		timeout: cfg.Timeout,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

func (h *HTTPScorer) Name() string { return "http" }

type scoreRequest struct {
	Features Features `json:"features"`
}

type scoreResponse struct {
	Score float64 `json:"score"`
}

func (h *HTTPScorer) Score(ctx context.Context, f Features) (float64, error) {
	body, err := json.Marshal(scoreRequest{Features: f})
	if err != nil {
		return 0, fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("status %d: %s", resp.StatusCode, string(b))
	}

	var out scoreResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, fmt.Errorf("decode: %w", err)
	}
	return out.Score, nil
}

func (h *HTTPScorer) Close() error {
	h.client.CloseIdleConnections()
	return nil
}
