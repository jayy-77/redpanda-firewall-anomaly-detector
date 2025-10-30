// Package featurestore persists windowed feature vectors so that training
// and online scoring see the same numbers. Currently backed by Redis with
// a TTL'd hash per (log_source, window_end). Replaceable with any KV.
package featurestore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// Record is the unit written to the store.
type Record struct {
	LogSource   string             `json:"log_source"`
	WindowStart time.Time          `json:"window_start"`
	WindowEnd   time.Time          `json:"window_end"`
	Features    map[string]float64 `json:"features"`
	Score       float64            `json:"score"`
	Anomaly     bool               `json:"anomaly"`
	Scorer      string             `json:"scorer"`
}

// RedisStore is a feature store backed by Redis hashes.
type RedisStore struct {
	client *redis.Client
	prefix string
	ttl    time.Duration
}

type Config struct {
	Client *redis.Client
	Prefix string
	TTL    time.Duration
}

func NewRedisStore(cfg Config) *RedisStore {
	if cfg.Prefix == "" {
		cfg.Prefix = "fw:features"
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 24 * time.Hour
	}
	return &RedisStore{client: cfg.Client, prefix: cfg.Prefix, ttl: cfg.TTL}
}

func (s *RedisStore) key(r Record) string {
	return fmt.Sprintf("%s:%s:%d", s.prefix, r.LogSource, r.WindowEnd.UnixNano())
}

// Put writes a record and sets a TTL.
func (s *RedisStore) Put(ctx context.Context, r Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return s.client.Set(ctx, s.key(r), b, s.ttl).Err()
}

// Range returns all records for a source between start and end (inclusive).
// Scans by key pattern, so suitable for small lookups, not bulk export.
func (s *RedisStore) Range(ctx context.Context, source string, start, end time.Time) ([]Record, error) {
	pattern := fmt.Sprintf("%s:%s:*", s.prefix, source)
	iter := s.client.Scan(ctx, 0, pattern, 0).Iterator()
	var out []Record
	for iter.Next(ctx) {
		val, err := s.client.Get(ctx, iter.Val()).Bytes()
		if err != nil {
			continue
		}
		var r Record
		if err := json.Unmarshal(val, &r); err != nil {
			continue
		}
		if r.WindowEnd.Before(start) || r.WindowEnd.After(end) {
			continue
		}
		out = append(out, r)
	}
	return out, iter.Err()
}
