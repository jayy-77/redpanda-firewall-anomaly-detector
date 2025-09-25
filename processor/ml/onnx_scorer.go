package ml

import (
	"context"
	"errors"
	"fmt"
)

// ONNXScorer is a stub for in-process ONNX inference. Wiring the actual
// runtime (e.g. github.com/yalue/onnxruntime_go) needs the platform shared
// library on PATH and a built model — both deployment-time concerns. The
// stub returns ErrONNXNotConfigured so misconfiguration fails loudly
// instead of silently falling back to garbage scores.
type ONNXScorer struct {
	modelPath    string
	featureOrder []string
}

type ONNXScorerConfig struct {
	ModelPath    string
	FeatureOrder []string
}

var ErrONNXNotConfigured = errors.New("ONNX runtime not built in; rebuild with -tags onnx and the onnxruntime shared library on PATH")

func NewONNXScorer(cfg ONNXScorerConfig) (*ONNXScorer, error) {
	if cfg.ModelPath == "" {
		return nil, fmt.Errorf("ONNXScorer: ModelPath required")
	}
	if len(cfg.FeatureOrder) == 0 {
		return nil, fmt.Errorf("ONNXScorer: FeatureOrder required")
	}
	return &ONNXScorer{modelPath: cfg.ModelPath, featureOrder: cfg.FeatureOrder}, nil
}

func (s *ONNXScorer) Name() string { return "onnx" }

func (s *ONNXScorer) Score(_ context.Context, _ Features) (float64, error) {
	return 0, ErrONNXNotConfigured
}

func (s *ONNXScorer) Close() error { return nil }
