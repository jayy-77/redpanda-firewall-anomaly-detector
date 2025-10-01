package ml

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeuristicScorer_RangeAndBehavior(t *testing.T) {
	s := NewHeuristicScorer()

	// All low signals → low score.
	score, err := s.Score(context.Background(), Features{
		"percent_change":     5.0,
		"peak_to_mean_ratio": 1.2,
		"std_dev":            1.0,
		"mean_value":         10.0,
		"unique_ips":         5.0,
	})
	require.NoError(t, err)
	assert.Less(t, score, 0.5)

	// All high signals → maxed out.
	score, err = s.Score(context.Background(), Features{
		"percent_change":     200.0,
		"peak_to_mean_ratio": 5.0,
		"std_dev":            50.0,
		"mean_value":         10.0,
		"unique_ips":         500.0,
	})
	require.NoError(t, err)
	assert.InDelta(t, 1.0, score, 1e-9)
}

func TestHTTPScorer_Roundtrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"score": 0.42}`))
	}))
	defer srv.Close()

	s := NewHTTPScorer(HTTPScorerConfig{URL: srv.URL})
	defer s.Close()

	score, err := s.Score(context.Background(), Features{"mean_value": 1})
	require.NoError(t, err)
	assert.InDelta(t, 0.42, score, 1e-9)
}

func TestHTTPScorer_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := NewHTTPScorer(HTTPScorerConfig{URL: srv.URL})
	defer s.Close()

	_, err := s.Score(context.Background(), Features{})
	require.Error(t, err)
}

func TestFactory_HeuristicDefault(t *testing.T) {
	s, err := NewScorer(FactoryConfig{})
	require.NoError(t, err)
	assert.Equal(t, "heuristic", s.Name())
}

func TestFactory_Unknown(t *testing.T) {
	_, err := NewScorer(FactoryConfig{Type: "nope"})
	require.Error(t, err)
}

func TestFactory_ONNXFallback(t *testing.T) {
	// Missing ModelPath → constructor fails. With FallbackToHeur it returns heuristic.
	s, err := NewScorer(FactoryConfig{Type: "onnx", FallbackToHeur: true})
	require.NoError(t, err)
	assert.Equal(t, "heuristic", s.Name())
}
