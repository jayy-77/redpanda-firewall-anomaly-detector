package ml

import (
	"strings"
	"time"
)

// FactoryConfig groups all scorer options under one struct so the processor
// can pass it straight through from the Benthos YAML field.
type FactoryConfig struct {
	Type           string
	ModelPath      string
	HTTPURL        string
	HTTPTimeoutMs  int
	FeatureOrder   []string
	FallbackToHeur bool
}

// NewScorer constructs the configured scorer. When FallbackToHeur is true
// and construction fails, the heuristic scorer is returned instead — the
// processor keeps running with a safe baseline rather than failing the
// whole pipeline.
func NewScorer(cfg FactoryConfig) (Scorer, error) {
	switch strings.ToLower(cfg.Type) {
	case "", "heuristic":
		return NewHeuristicScorer(), nil
	case "http":
		return NewHTTPScorer(HTTPScorerConfig{
			URL:     cfg.HTTPURL,
			Timeout: time.Duration(cfg.HTTPTimeoutMs) * time.Millisecond,
		}), nil
	case "onnx":
		s, err := NewONNXScorer(ONNXScorerConfig{
			ModelPath:    cfg.ModelPath,
			FeatureOrder: cfg.FeatureOrder,
		})
		if err != nil {
			if cfg.FallbackToHeur {
				return NewHeuristicScorer(), nil
			}
			return nil, err
		}
		return s, nil
	default:
		return nil, ErrUnknownScorer{Type: cfg.Type}
	}
}
