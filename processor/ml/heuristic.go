package ml

import (
	"context"
	"math"
)

// HeuristicScorer is the original placeholder scoring rule, extracted into
// its own type so it can be A/B'd against ML-based scorers. It's also a
// safe fallback when the configured ML scorer fails to load.
type HeuristicScorer struct{}

func NewHeuristicScorer() *HeuristicScorer { return &HeuristicScorer{} }

func (h *HeuristicScorer) Name() string { return "heuristic" }

func (h *HeuristicScorer) Score(_ context.Context, f Features) (float64, error) {
	score := 0.0
	if math.Abs(f["percent_change"]) > 50 {
		score += 0.3
	}
	if f["peak_to_mean_ratio"] > 3 {
		score += 0.2
	}
	if f["std_dev"] > f["mean_value"] {
		score += 0.2
	}
	if f["unique_ips"] > 100 {
		score += 0.3
	}
	return math.Min(score, 1.0), nil
}

func (h *HeuristicScorer) Close() error { return nil }
