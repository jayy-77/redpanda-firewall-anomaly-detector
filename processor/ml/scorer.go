// Package ml defines the anomaly scoring contract and ships three concrete
// implementations the processor can swap between at config time: a stateless
// heuristic baseline, an HTTP client to a Python model server, and an ONNX
// in-process runtime path.
package ml

import (
	"context"
	"fmt"
)

// Features is the 7-dimensional vector emitted by the sliding-window
// aggregator. Kept as a map so the schema can evolve without breaking the
// scorer interface; concrete scorers normalize this internally.
type Features map[string]float64

// Scorer turns aggregated features into an anomaly score in [0, 1].
// Implementations MUST be safe for concurrent use from multiple goroutines.
type Scorer interface {
	// Name identifies the scorer for logging and metrics.
	Name() string
	// Score returns an anomaly score in [0,1]; higher = more anomalous.
	Score(ctx context.Context, f Features) (float64, error)
	// Close releases any resources (network connections, ONNX sessions).
	Close() error
}

// ErrUnknownScorer is returned when configuration specifies an unrecognized
// scorer type. The caller decides whether to fall back to heuristic mode
// or fail loudly.
type ErrUnknownScorer struct{ Type string }

func (e ErrUnknownScorer) Error() string { return fmt.Sprintf("unknown scorer type %q", e.Type) }
