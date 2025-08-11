package processor

import (
	"context"
	"encoding/json"
	"math"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/redpanda-data/benthos/v4/public/service"
	"gonum.org/v1/gonum/stat"
)

func init() {
	configSpec := service.NewConfigSpec().
		Beta().
		Categories("Integration").
		Summary("Detects anomalies in firewall logs using ML models and sliding windows").
		Description(`
This processor reads firewall logs from Redis, maintains sliding time windows for each log source,
aggregates features, applies ML anomaly detection, and routes results to different Kafka topics.

Features:
- Sliding time window aggregation per log source
- Configurable ML model loading (Isolation Forest)
- Feature extraction: mean, std dev, max, min, percent change, unique IPs, peak-to-mean ratio
- Anomaly scoring and threshold-based routing
- Redis integration for log consumption
- Kafka/Redpanda output routing
`).
		Field(service.NewIntField("window_seconds").
			Description("Duration of the sliding time window in seconds").
			Default(60)).
		Field(service.NewStringField("model_path").
			Description("Path to the pre-trained ML model file (.pkl)").
			Default("/etc/plugin/model.pkl")).
		Field(service.NewFloatField("score_threshold").
			Description("Threshold for anomaly detection (0.0 to 1.0)").
			Default(0.7)).
		Field(service.NewObjectField("redis_config",
			service.NewStringField("address").
				Description("Redis server address").
				Default("localhost:6379"),
			service.NewStringField("password").
				Description("Redis password").
				Optional(),
			service.NewIntField("db").
				Description("Redis database number").
				Default(0),
			service.NewStringField("key").
				Description("Redis list key containing firewall logs").
				Default("firewall_logs"),
		)).
		Field(service.NewObjectField("kafka_config",
			service.NewStringListField("brokers").
				Description("List of Kafka/Redpanda broker addresses").
				Default([]string{"localhost:9092"}),
			service.NewStringField("anomaly_topic").
				Description("Topic for anomalous events").
				Default("firewall-anomalies"),
			service.NewStringField("normal_topic").
				Description("Topic for normal events").
				Default("firewall-normal"),
		)).
		Field(service.NewObjectMapField("sources",
			service.NewStringField("metric").
				Description("Metric field to extract from logs for this source").
				Default("connection_count"),
		).
			Description("Configuration for different log sources").
			Default(map[string]interface{}{
				"fortinet.firewall": map[string]interface{}{
					"metric": "connection_count",
				},
				"paloalto.firewall": map[string]interface{}{
					"metric": "bytes_sent",
				},
			}))

	constructor := func(conf *service.ParsedConfig, mgr *service.Resources) (service.Processor, error) {
		return newFirewallAnomalyDetector(conf, mgr)
	}

	err := service.RegisterProcessor("firewall_anomaly_detector", configSpec, constructor)
	if err != nil {
		panic(err)
	}
}

//------------------------------------------------------------------------------

type FirewallLog struct {
	Timestamp       time.Time              `json:"timestamp"`
	LogSource       string                 `json:"log_source"`
	SourceIP        string                 `json:"source_ip"`
	DestIP          string                 `json:"dest_ip"`
	ConnectionCount int                    `json:"connection_count,omitempty"`
	BytesSent       int64                  `json:"bytes_sent,omitempty"`
	BytesRecv       int64                  `json:"bytes_recv,omitempty"`
	Action          string                 `json:"action"`
	Severity        string                 `json:"severity"`
	Raw             map[string]interface{} `json:"raw"`
}

type WindowData struct {
	Values    []float64
	IPs       map[string]bool
	LastMean  float64
	StartTime time.Time
	EndTime   time.Time
}

type FirewallAnomalyDetector struct {
	logger  *service.Logger
	metrics *service.Metrics

	windowSeconds  int
	modelPath      string
	scoreThreshold float64

	redisClient *redis.Client
	redisKey    string

	kafkaBrokers []string
	anomalyTopic string
	normalTopic  string

	sources map[string]string // log_source -> metric_field

	windows      map[string]*WindowData
	windowsMutex sync.RWMutex

	// Metrics
	processedLogs     *service.MetricCounter
	anomaliesDetected *service.MetricCounter
	windowsCreated    *service.MetricCounter
}

func newFirewallAnomalyDetector(conf *service.ParsedConfig, mgr *service.Resources) (*FirewallAnomalyDetector, error) {
	windowSeconds, err := conf.FieldInt("window_seconds")
	if err != nil {
		return nil, err
	}

	modelPath, err := conf.FieldString("model_path")
	if err != nil {
		return nil, err
	}

	scoreThreshold, err := conf.FieldFloat("score_threshold")
	if err != nil {
		return nil, err
	}

	// Parse Redis config
	redisAddr, err := conf.FieldString("redis_config", "address")
	if err != nil {
		return nil, err
	}

	redisPassword, _ := conf.FieldString("redis_config", "password")
	redisDB, err := conf.FieldInt("redis_config", "db")
	if err != nil {
		return nil, err
	}

	redisKey, err := conf.FieldString("redis_config", "key")
	if err != nil {
		return nil, err
	}

	// Parse Kafka config
	kafkaBrokers, err := conf.FieldStringList("kafka_config", "brokers")
	if err != nil {
		return nil, err
	}

	anomalyTopic, err := conf.FieldString("kafka_config", "anomaly_topic")
	if err != nil {
		return nil, err
	}

	normalTopic, err := conf.FieldString("kafka_config", "normal_topic")
	if err != nil {
		return nil, err
	}

	// Parse sources config
	sourcesMap, err := conf.FieldObjectMap("sources")
	if err != nil {
		return nil, err
	}

	sources := make(map[string]string)
	for source, sourceConf := range sourcesMap {
		metric, err := sourceConf.FieldString("metric")
		if err != nil {
			return nil, err
		}
		sources[source] = metric
	}

	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       redisDB,
	})

	detector := &FirewallAnomalyDetector{
		logger:            mgr.Logger(),
		metrics:           mgr.Metrics(),
		windowSeconds:     windowSeconds,
		modelPath:         modelPath,
		scoreThreshold:    scoreThreshold,
		redisClient:       redisClient,
		redisKey:          redisKey,
		kafkaBrokers:      kafkaBrokers,
		anomalyTopic:      anomalyTopic,
		normalTopic:       normalTopic,
		sources:           sources,
		windows:           make(map[string]*WindowData),
		processedLogs:     mgr.Metrics().NewCounter("processed_logs"),
		anomaliesDetected: mgr.Metrics().NewCounter("anomalies_detected"),
		windowsCreated:    mgr.Metrics().NewCounter("windows_created"),
	}

	// Load ML model (placeholder - would integrate with actual ML library)
	detector.logger.Infof("Loading ML model from: %s", modelPath)

	return detector, nil
}

func (f *FirewallAnomalyDetector) Process(ctx context.Context, m *service.Message) (service.MessageBatch, error) {
	// Read logs from Redis
	logs, err := f.readLogsFromRedis(ctx)
	if err != nil {
		f.logger.Errorf("Failed to read logs from Redis: %v", err)
		return nil, err
	}

	var results []*service.Message

	for _, log := range logs {
		// Process each log through sliding windows
		result, err := f.processLog(ctx, log)
		if err != nil {
			f.logger.Errorf("Failed to process log: %v", err)
			continue
		}

		if result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

func (f *FirewallAnomalyDetector) readLogsFromRedis(ctx context.Context) ([]FirewallLog, error) {
	// Read from Redis list
	result, err := f.redisClient.LRange(ctx, f.redisKey, 0, -1).Result()
	if err != nil {
		return nil, err
	}

	var logs []FirewallLog
	for _, item := range result {
		var log FirewallLog
		if err := json.Unmarshal([]byte(item), &log); err != nil {
			f.logger.Warnf("Failed to parse log entry: %v", err)
			continue
		}
		logs = append(logs, log)
	}

	return logs, nil
}

func (f *FirewallAnomalyDetector) processLog(ctx context.Context, log FirewallLog) (*service.Message, error) {
	f.processedLogs.Incr(1)

	// Get metric field for this log source
	metricField, exists := f.sources[log.LogSource]
	if !exists {
		f.logger.Warnf("No configuration found for log source: %s", log.LogSource)
		return nil, nil
	}

	// Extract metric value
	var metricValue float64
	switch metricField {
	case "connection_count":
		metricValue = float64(log.ConnectionCount)
	case "bytes_sent":
		metricValue = float64(log.BytesSent)
	case "bytes_recv":
		metricValue = float64(log.BytesRecv)
	default:
		f.logger.Warnf("Unknown metric field: %s", metricField)
		return nil, nil
	}

	// Update sliding window
	windowKey := log.LogSource
	f.updateWindow(windowKey, metricValue, log.SourceIP, log.Timestamp)

	// Check if window is complete and ready for analysis
	window := f.getWindow(windowKey)
	if window == nil || time.Since(window.EndTime) < time.Duration(f.windowSeconds)*time.Second {
		return nil, nil
	}

	// Extract features
	features := f.extractFeatures(window)

	// Score with ML model
	anomalyScore := f.scoreAnomaly(features)

	// Determine if anomaly
	isAnomaly := anomalyScore >= f.scoreThreshold

	// Create result message
	result := map[string]interface{}{
		"timestamp":     window.EndTime,
		"log_source":    log.LogSource,
		"window_start":  window.StartTime,
		"window_end":    window.EndTime,
		"anomaly_score": anomalyScore,
		"is_anomaly":    isAnomaly,
		"reason":        "hike_rate_detected",
		"features":      features,
		"metric_field":  metricField,
		"metric_value":  metricValue,
	}

	// Set topic based on anomaly status
	topic := f.normalTopic
	if isAnomaly {
		topic = f.anomalyTopic
		f.anomaliesDetected.Incr(1)
	}

	// Create message
	resultMsg := service.NewMessage(nil)
	resultMsg.SetStructured(result)
	resultMsg.MetaSet("topic", topic)

	// Clear the window after processing
	f.clearWindow(windowKey)

	return resultMsg, nil
}

func (f *FirewallAnomalyDetector) updateWindow(windowKey string, value float64, sourceIP string, timestamp time.Time) {
	f.windowsMutex.Lock()
	defer f.windowsMutex.Unlock()

	window, exists := f.windows[windowKey]
	if !exists {
		window = &WindowData{
			Values:    []float64{},
			IPs:       make(map[string]bool),
			StartTime: timestamp,
			EndTime:   timestamp.Add(time.Duration(f.windowSeconds) * time.Second),
		}
		f.windows[windowKey] = window
		f.windowsCreated.Incr(1)
	}

	// Add value to window
	window.Values = append(window.Values, value)
	window.IPs[sourceIP] = true

	// Update end time
	if timestamp.After(window.EndTime) {
		window.EndTime = timestamp.Add(time.Duration(f.windowSeconds) * time.Second)
	}
}

func (f *FirewallAnomalyDetector) getWindow(windowKey string) *WindowData {
	f.windowsMutex.RLock()
	defer f.windowsMutex.RUnlock()
	return f.windows[windowKey]
}

func (f *FirewallAnomalyDetector) clearWindow(windowKey string) {
	f.windowsMutex.Lock()
	defer f.windowsMutex.Unlock()
	delete(f.windows, windowKey)
}

func (f *FirewallAnomalyDetector) extractFeatures(window *WindowData) map[string]float64 {
	if len(window.Values) == 0 {
		return map[string]float64{
			"mean_value":         0.0,
			"std_dev":            0.0,
			"max_value":          0.0,
			"min_value":          0.0,
			"percent_change":     0.0,
			"unique_ips":         0.0,
			"peak_to_mean_ratio": 0.0,
		}
	}

	// Calculate basic statistics
	mean := stat.Mean(window.Values, nil)
	stdDev := stat.StdDev(window.Values, nil)

	// Find max and min
	max := window.Values[0]
	min := window.Values[0]
	for _, v := range window.Values {
		if v > max {
			max = v
		}
		if v < min {
			min = v
		}
	}

	// Calculate percent change from previous window
	percentChange := 0.0
	if window.LastMean > 0 {
		percentChange = ((mean - window.LastMean) / window.LastMean) * 100
	}

	// Count unique IPs
	uniqueIPs := float64(len(window.IPs))

	// Calculate peak to mean ratio
	peakToMeanRatio := 0.0
	if mean > 0 {
		peakToMeanRatio = max / mean
	}

	return map[string]float64{
		"mean_value":         mean,
		"std_dev":            stdDev,
		"max_value":          max,
		"min_value":          min,
		"percent_change":     percentChange,
		"unique_ips":         uniqueIPs,
		"peak_to_mean_ratio": peakToMeanRatio,
	}
}

func (f *FirewallAnomalyDetector) scoreAnomaly(features map[string]float64) float64 {
	// This is a placeholder implementation
	// In a real implementation, you would load and use the actual ML model

	// Simple heuristic-based scoring for demonstration
	score := 0.0

	// Higher score for high percent change
	if math.Abs(features["percent_change"]) > 50 {
		score += 0.3
	}

	// Higher score for high peak-to-mean ratio
	if features["peak_to_mean_ratio"] > 3 {
		score += 0.2
	}

	// Higher score for high standard deviation
	if features["std_dev"] > features["mean_value"] {
		score += 0.2
	}

	// Higher score for many unique IPs
	if features["unique_ips"] > 100 {
		score += 0.3
	}

	return math.Min(score, 1.0)
}

func (f *FirewallAnomalyDetector) Close(ctx context.Context) error {
	if f.redisClient != nil {
		return f.redisClient.Close()
	}
	return nil
}
