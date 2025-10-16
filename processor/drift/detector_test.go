package drift

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReservoir_BoundedSize(t *testing.T) {
	r := NewReservoir(5)
	for i := 0; i < 20; i++ {
		r.Add(float64(i))
	}
	assert.Len(t, r.Snapshot(), 5)
}

func TestPSI_NoDrift(t *testing.T) {
	rng := rand.New(rand.NewSource(0))
	a := make([]float64, 5000)
	b := make([]float64, 5000)
	for i := range a {
		a[i] = rng.NormFloat64()
		b[i] = rng.NormFloat64()
	}
	assert.Less(t, PSI(a, b, 10), 0.1)
}

func TestPSI_DriftDetected(t *testing.T) {
	rng := rand.New(rand.NewSource(0))
	a := make([]float64, 5000)
	b := make([]float64, 5000)
	for i := range a {
		a[i] = rng.NormFloat64()
		b[i] = rng.NormFloat64() + 2.0
	}
	assert.Greater(t, PSI(a, b, 10), 0.25)
}

func TestDetector_TracksPerFeature(t *testing.T) {
	d := NewDetector(Config{ReservoirCapacity: 200, PSIThreshold: 0.2})
	for i := 0; i < 200; i++ {
		d.Observe("mean_value", float64(i%10))
		d.Observe("std_dev", float64(i%5))
	}
	// Shifted distribution
	for i := 0; i < 200; i++ {
		d.Update("mean_value", float64(i%10)+5.0)
		d.Update("std_dev", float64(i%5))
	}
	rep := d.Report()
	assert.Greater(t, rep["mean_value"], 0.1)
	assert.Less(t, rep["std_dev"], 0.1)
}
