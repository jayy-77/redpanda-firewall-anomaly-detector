package benchmarks

import (
	"context"
	"testing"

	"github.com/jaykumar/redpanda-firewall-anomaly-detector/processor/ml"
)

func BenchmarkHeuristicScorer(b *testing.B) {
	s := ml.NewHeuristicScorer()
	f := ml.Features{
		"percent_change":     30.0,
		"peak_to_mean_ratio": 2.0,
		"std_dev":            5.0,
		"mean_value":         10.0,
		"unique_ips":         50.0,
	}
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = s.Score(ctx, f)
	}
}
