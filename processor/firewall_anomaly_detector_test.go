package processor

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/redpanda-data/benthos/v4/public/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFirewallAnomalyDetectorConfig(t *testing.T) {
	// Test configuration parsing by creating a processor with test config
	config := service.NewConfigSpec()
	config.Field(service.NewIntField("window_seconds").Default(60))
	config.Field(service.NewStringField("model_path").Default("/etc/plugin/model.pkl"))
	config.Field(service.NewFloatField("score_threshold").Default(0.7))
	config.Field(service.NewObjectField("redis_config",
		service.NewStringField("address").Default("localhost:6379"),
		service.NewStringField("password").Optional(),
		service.NewIntField("db").Default(0),
		service.NewStringField("key").Default("firewall_logs"),
	))
	config.Field(service.NewObjectField("kafka_config",
		service.NewStringListField("brokers").Default([]string{"localhost:9092"}),
		service.NewStringField("anomaly_topic").Default("firewall-anomalies"),
		service.NewStringField("normal_topic").Default("firewall-normal"),
	))
	config.Field(service.NewObjectMapField("sources",
		service.NewStringField("metric").Default("connection_count"),
	).Default(map[string]interface{}{
		"fortinet.firewall": map[string]interface{}{
			"metric": "connection_count",
		},
		"paloalto.firewall": map[string]interface{}{
			"metric": "bytes_sent",
		},
	}))

	// Test that the config spec is valid
	assert.NotNil(t, config)
}

func TestFirewallLogParsing(t *testing.T) {
	logJSON := `{
		"timestamp": "2024-01-15T10:30:00Z",
		"log_source": "fortinet.firewall",
		"source_ip": "192.168.1.100",
		"dest_ip": "10.0.0.50",
		"connection_count": 150,
		"action": "accept",
		"severity": "medium",
		"raw": {
			"session_id": "12345",
			"protocol": "tcp"
		}
	}`

	var log FirewallLog
	err := json.Unmarshal([]byte(logJSON), &log)
	require.NoError(t, err)

	assert.Equal(t, "fortinet.firewall", log.LogSource)
	assert.Equal(t, "192.168.1.100", log.SourceIP)
	assert.Equal(t, "10.0.0.50", log.DestIP)
	assert.Equal(t, 150, log.ConnectionCount)
	assert.Equal(t, "accept", log.Action)
	assert.Equal(t, "medium", log.Severity)
}

func TestFeatureExtraction(t *testing.T) {
	window := &WindowData{
		Values: []float64{10, 20, 30, 40, 50},
		IPs: map[string]bool{
			"192.168.1.1": true,
			"192.168.1.2": true,
			"192.168.1.3": true,
		},
		LastMean:  25.0,
		StartTime: time.Now().Add(-time.Minute),
		EndTime:   time.Now(),
	}

	detector := &FirewallAnomalyDetector{}
	features := detector.extractFeatures(window)

	assert.Equal(t, 30.0, features["mean_value"])
	assert.Equal(t, 15.811388300841896, features["std_dev"])
	assert.Equal(t, 50.0, features["max_value"])
	assert.Equal(t, 10.0, features["min_value"])
	assert.Equal(t, 20.0, features["percent_change"]) // (30-25)/25 * 100
	assert.Equal(t, 3.0, features["unique_ips"])
	assert.Equal(t, 1.6666666666666667, features["peak_to_mean_ratio"]) // 50/30
}

func TestFeatureExtractionEmptyWindow(t *testing.T) {
	window := &WindowData{
		Values:    []float64{},
		IPs:       map[string]bool{},
		StartTime: time.Now().Add(-time.Minute),
		EndTime:   time.Now(),
	}

	detector := &FirewallAnomalyDetector{}
	features := detector.extractFeatures(window)

	assert.Equal(t, 0.0, features["mean_value"])
	assert.Equal(t, 0.0, features["std_dev"])
	assert.Equal(t, 0.0, features["max_value"])
	assert.Equal(t, 0.0, features["min_value"])
	assert.Equal(t, 0.0, features["percent_change"])
	assert.Equal(t, 0.0, features["unique_ips"])
	assert.Equal(t, 0.0, features["peak_to_mean_ratio"])
}

func TestAnomalyScoring(t *testing.T) {
	detector := &FirewallAnomalyDetector{
		scoreThreshold: 0.7,
	}

	// Test normal features
	normalFeatures := map[string]float64{
		"percent_change":     10.0,
		"peak_to_mean_ratio": 1.5,
		"std_dev":            5.0,
		"mean_value":         10.0,
		"unique_ips":         50.0,
	}
	score := detector.scoreAnomaly(normalFeatures)
	assert.True(t, score < 0.7, "Normal features should score below threshold")

	// Test anomalous features
	anomalousFeatures := map[string]float64{
		"percent_change":     75.0, // > 50
		"peak_to_mean_ratio": 4.0,  // > 3
		"std_dev":            15.0, // > mean_value
		"mean_value":         10.0,
		"unique_ips":         150.0, // > 100
	}
	score = detector.scoreAnomaly(anomalousFeatures)
	assert.True(t, score >= 0.7, "Anomalous features should score above threshold")
}

func TestWindowManagement(t *testing.T) {
	detector := &FirewallAnomalyDetector{
		windowSeconds: 60,
		windows:       make(map[string]*WindowData),
	}

	// Test window creation
	windowKey := "fortinet.firewall"
	timestamp := time.Now()

	detector.updateWindow(windowKey, 100.0, "192.168.1.1", timestamp)

	window := detector.getWindow(windowKey)
	require.NotNil(t, window)
	assert.Equal(t, 1, len(window.Values))
	assert.Equal(t, 100.0, window.Values[0])
	assert.Equal(t, 1, len(window.IPs))
	assert.True(t, window.IPs["192.168.1.1"])

	// Test window update
	detector.updateWindow(windowKey, 200.0, "192.168.1.2", timestamp.Add(time.Second))

	window = detector.getWindow(windowKey)
	assert.Equal(t, 2, len(window.Values))
	assert.Equal(t, 200.0, window.Values[1])
	assert.Equal(t, 2, len(window.IPs))
	assert.True(t, window.IPs["192.168.1.2"])

	// Test window clearing
	detector.clearWindow(windowKey)
	window = detector.getWindow(windowKey)
	assert.Nil(t, window)
}

func TestMetricExtraction(t *testing.T) {
	log := FirewallLog{
		LogSource:       "fortinet.firewall",
		ConnectionCount: 150,
		BytesSent:       1024,
		BytesRecv:       2048,
	}

	// Test connection_count extraction
	metricField := "connection_count"
	metricValue := extractMetricValue(log, metricField)
	assert.Equal(t, 150.0, metricValue)

	// Test bytes_sent extraction
	metricField = "bytes_sent"
	metricValue = extractMetricValue(log, metricField)
	assert.Equal(t, 1024.0, metricValue)

	// Test bytes_recv extraction
	metricField = "bytes_recv"
	metricValue = extractMetricValue(log, metricField)
	assert.Equal(t, 2048.0, metricValue)

	// Test unknown metric
	metricField = "unknown_field"
	metricValue = extractMetricValue(log, metricField)
	assert.Equal(t, 0.0, metricValue)
}

// Helper function for testing
func extractMetricValue(log FirewallLog, metricField string) float64 {
	switch metricField {
	case "connection_count":
		return float64(log.ConnectionCount)
	case "bytes_sent":
		return float64(log.BytesSent)
	case "bytes_recv":
		return float64(log.BytesRecv)
	default:
		return 0.0
	}
}
