// Package drift implements streaming drift detection for the windowed
// feature vector. Rolling reservoirs maintain a baseline distribution
// per feature; on each new feature update we run a KS-style statistic
// and emit a drift event when it crosses threshold.
//
// The math intentionally favors speed over textbook correctness: the
// reservoir sketches are bounded so memory is O(1) per feature, and the
// drift statistic is the max-bin PSI rather than full empirical CDF KS.
// For deep statistical rigor, export the same feature stream to the
// offline drift report instead.
package drift

import (
	"math"
	"sort"
	"sync"
)

// Reservoir is a fixed-size sample that approximates a feature's distribution.
type Reservoir struct {
	mu     sync.Mutex
	values []float64
	cap    int
	count  int
}

func NewReservoir(capacity int) *Reservoir {
	if capacity <= 0 {
		capacity = 1024
	}
	return &Reservoir{values: make([]float64, 0, capacity), cap: capacity}
}

// Add inserts a value. When the reservoir is at capacity, it drops the
// oldest sample (FIFO) — this is a fixed-window approximation rather
// than true reservoir sampling, which fits our use of "compare last N
// observations to a baseline of N observations".
func (r *Reservoir) Add(v float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count++
	if len(r.values) < r.cap {
		r.values = append(r.values, v)
		return
	}
	copy(r.values, r.values[1:])
	r.values[len(r.values)-1] = v
}

// Snapshot returns a copy of the current reservoir contents.
func (r *Reservoir) Snapshot() []float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]float64, len(r.values))
	copy(out, r.values)
	return out
}

// PSI computes Population Stability Index between two samples with
// equal-frequency binning derived from `expected`.
func PSI(expected, actual []float64, bins int) float64 {
	if len(expected) == 0 || len(actual) == 0 {
		return 0
	}
	if bins <= 0 {
		bins = 10
	}
	exp := append([]float64(nil), expected...)
	sort.Float64s(exp)
	cuts := make([]float64, bins+1)
	cuts[0] = math.Inf(-1)
	cuts[bins] = math.Inf(1)
	for i := 1; i < bins; i++ {
		cuts[i] = exp[(i*len(exp))/bins]
	}
	expBins := histogram(expected, cuts)
	actBins := histogram(actual, cuts)
	expSum := sum(expBins)
	actSum := sum(actBins)
	if expSum == 0 || actSum == 0 {
		return 0
	}
	var psi float64
	for i := range expBins {
		ep := math.Max(expBins[i]/expSum, 1e-6)
		ap := math.Max(actBins[i]/actSum, 1e-6)
		psi += (ap - ep) * math.Log(ap/ep)
	}
	return psi
}

func histogram(values []float64, cuts []float64) []float64 {
	out := make([]float64, len(cuts)-1)
	for _, v := range values {
		idx := sort.Search(len(cuts), func(i int) bool { return cuts[i] > v }) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(out) {
			idx = len(out) - 1
		}
		out[idx]++
	}
	return out
}

func sum(xs []float64) float64 {
	s := 0.0
	for _, v := range xs {
		s += v
	}
	return s
}

// Detector tracks one reservoir per feature and emits drift events.
type Detector struct {
	mu           sync.Mutex
	baseline     map[string]*Reservoir
	current      map[string]*Reservoir
	capacity     int
	bins         int
	psiThreshold float64
}

type Config struct {
	ReservoirCapacity int
	Bins              int
	PSIThreshold      float64
}

func NewDetector(cfg Config) *Detector {
	if cfg.ReservoirCapacity <= 0 {
		cfg.ReservoirCapacity = 1024
	}
	if cfg.Bins <= 0 {
		cfg.Bins = 10
	}
	if cfg.PSIThreshold <= 0 {
		cfg.PSIThreshold = 0.2
	}
	return &Detector{
		baseline:     make(map[string]*Reservoir),
		current:      make(map[string]*Reservoir),
		capacity:     cfg.ReservoirCapacity,
		bins:         cfg.Bins,
		psiThreshold: cfg.PSIThreshold,
	}
}

func (d *Detector) getOrInit(m map[string]*Reservoir, key string) *Reservoir {
	r, ok := m[key]
	if !ok {
		r = NewReservoir(d.capacity)
		m[key] = r
	}
	return r
}

// Observe records a baseline value (used during warmup).
func (d *Detector) Observe(feature string, value float64) {
	d.mu.Lock()
	r := d.getOrInit(d.baseline, feature)
	d.mu.Unlock()
	r.Add(value)
}

// Update records a runtime value and returns its PSI vs. the baseline.
func (d *Detector) Update(feature string, value float64) (psi float64, drift bool) {
	d.mu.Lock()
	cur := d.getOrInit(d.current, feature)
	base := d.getOrInit(d.baseline, feature)
	d.mu.Unlock()
	cur.Add(value)
	p := PSI(base.Snapshot(), cur.Snapshot(), d.bins)
	return p, p >= d.psiThreshold
}

// Report returns the current PSI per feature.
func (d *Detector) Report() map[string]float64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]float64, len(d.current))
	for k, r := range d.current {
		base, ok := d.baseline[k]
		if !ok {
			continue
		}
		out[k] = PSI(base.Snapshot(), r.Snapshot(), d.bins)
	}
	return out
}
