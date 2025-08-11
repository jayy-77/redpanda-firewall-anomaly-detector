# Firewall Anomaly Detector Plugin

A Redpanda Connect (Benthos) processor plugin that detects anomalies in firewall logs using machine learning and sliding time windows.

## Overview

The Firewall Anomaly Detector plugin processes firewall logs from Redis, maintains sliding time windows for each log source, extracts statistical features, applies ML-based anomaly detection, and routes results to different Kafka topics based on anomaly scores.

## Features

- **Sliding Time Windows**: Configurable time windows (default: 60 seconds) for each log source
- **Feature Extraction**: Calculates statistical features including:
  - Mean value
  - Standard deviation
  - Maximum and minimum values
  - Percent change from previous window
  - Unique IP addresses count
  - Peak-to-mean ratio
- **ML Model Integration**: Supports pre-trained Isolation Forest models
- **Multi-Source Support**: Configurable for different firewall vendors (Fortinet, Palo Alto, Checkpoint, etc.)
- **Redis Integration**: Reads logs from Redis lists
- **Kafka Routing**: Routes anomalies and normal events to separate topics
- **Metrics & Monitoring**: Built-in metrics for processed logs, anomalies detected, and windows created

## Configuration

### Basic Configuration

```yaml
pipeline:
  processors:
  - firewall_anomaly_detector:
      window_seconds: 60
      model_path: "/etc/plugin/model.pkl"
      score_threshold: 0.7
      redis_config:
        address: "localhost:6379"
        password: ""
        db: 0
        key: "firewall_logs"
      kafka_config:
        brokers: ["localhost:9092"]
        anomaly_topic: "firewall-anomalies"
        normal_topic: "firewall-normal"
      sources:
        fortinet.firewall:
          metric: "connection_count"
        paloalto.firewall:
          metric: "bytes_sent"
        checkpoint.firewall:
          metric: "bytes_recv"
```

### Advanced Configuration

```yaml
pipeline:
  processors:
  - firewall_anomaly_detector:
      window_seconds: 300  # 5 minutes for more stable patterns
      model_path: "/models/isolation_forest_v2.pkl"
      score_threshold: 0.85  # Higher threshold for production
      redis_config:
        address: "redis-cluster:6379"
        password: "${REDIS_PASSWORD}"
        db: 1
        key: "firewall_logs"
      kafka_config:
        brokers: 
          - "kafka1:9092"
          - "kafka2:9092"
          - "kafka3:9092"
        anomaly_topic: "security-anomalies"
        normal_topic: "security-normal"
      sources:
        fortinet.firewall:
          metric: "connection_count"
        paloalto.firewall:
          metric: "bytes_sent"
        checkpoint.firewall:
          metric: "bytes_recv"
        cisco.asa:
          metric: "connection_count"
        juniper.srx:
          metric: "bytes_sent"
        sophos.firewall:
          metric: "connection_count"
```

## Configuration Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `window_seconds` | `int` | `60` | Duration of the sliding time window in seconds |
| `model_path` | `string` | `"/etc/plugin/model.pkl"` | Path to the pre-trained ML model file |
| `score_threshold` | `float` | `0.7` | Threshold for anomaly detection (0.0 to 1.0) |
| `redis_config.address` | `string` | `"localhost:6379"` | Redis server address |
| `redis_config.password` | `string` | `""` | Redis password (optional) |
| `redis_config.db` | `int` | `0` | Redis database number |
| `redis_config.key` | `string` | `"firewall_logs"` | Redis list key containing firewall logs |
| `kafka_config.brokers` | `[]string` | `["localhost:9092"]` | List of Kafka/Redpanda broker addresses |
| `kafka_config.anomaly_topic` | `string` | `"firewall-anomalies"` | Topic for anomalous events |
| `kafka_config.normal_topic` | `string` | `"firewall-normal"` | Topic for normal events |
| `sources` | `object` | See defaults | Configuration for different log sources |

## Input Log Format

The plugin expects firewall logs in JSON format with the following structure:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "log_source": "fortinet.firewall",
  "source_ip": "192.168.1.100",
  "dest_ip": "10.0.0.50",
  "connection_count": 150,
  "bytes_sent": 1024,
  "bytes_recv": 2048,
  "action": "accept",
  "severity": "medium",
  "raw": {
    "session_id": "12345",
    "protocol": "tcp",
    "src_port": 12345,
    "dst_port": 80
  }
}
```

### Required Fields

- `timestamp`: ISO 8601 timestamp
- `log_source`: Identifier for the firewall vendor/source
- `source_ip`: Source IP address
- `dest_ip`: Destination IP address

### Optional Fields

- `connection_count`: Number of connections (integer)
- `bytes_sent`: Bytes sent (integer)
- `bytes_recv`: Bytes received (integer)
- `action`: Firewall action (string)
- `severity`: Log severity (string)
- `raw`: Additional raw log data (object)

## Output Format

The plugin outputs structured messages with anomaly detection results:

```json
{
  "timestamp": "2024-01-15T10:31:00Z",
  "log_source": "fortinet.firewall",
  "window_start": "2024-01-15T10:30:00Z",
  "window_end": "2024-01-15T10:31:00Z",
  "anomaly_score": 0.85,
  "is_anomaly": true,
  "reason": "hike_rate_detected",
  "features": {
    "mean_value": 125.5,
    "std_dev": 45.2,
    "max_value": 250,
    "min_value": 50,
    "percent_change": 75.3,
    "unique_ips": 45,
    "peak_to_mean_ratio": 1.99
  },
  "metric_field": "connection_count",
  "metric_value": 200
}
```

## Feature Extraction

The plugin extracts the following statistical features from each time window:

### Statistical Features

- **mean_value**: Average of all metric values in the window
- **std_dev**: Standard deviation of metric values
- **max_value**: Maximum metric value in the window
- **min_value**: Minimum metric value in the window
- **percent_change**: Percentage change from previous window's mean
- **unique_ips**: Count of unique source IP addresses
- **peak_to_mean_ratio**: Ratio of maximum value to mean value

### Anomaly Scoring

The plugin uses a heuristic-based scoring system (with placeholder for ML model integration):

- High percent change (>50%): +0.3 points
- High peak-to-mean ratio (>3): +0.2 points
- High standard deviation (>mean): +0.2 points
- Many unique IPs (>100): +0.3 points

## Machine Learning Integration

The plugin is designed to integrate with pre-trained ML models:

1. **Model Loading**: Loads models from the specified path
2. **Feature Vector**: Converts extracted features to model input format
3. **Scoring**: Uses the model to generate anomaly scores
4. **Thresholding**: Applies configurable thresholds for classification

### Supported Model Types

- Isolation Forest
- One-Class SVM
- Local Outlier Factor (LOF)
- Autoencoders

## Metrics

The plugin provides the following metrics:

- `processed_logs`: Counter of processed log entries
- `anomalies_detected`: Counter of detected anomalies
- `windows_created`: Counter of created time windows

## Usage Examples

### Basic Setup

1. **Start Redis**:
   ```bash
   docker run -d -p 6379:6379 redis:alpine
   ```

2. **Generate Sample Data**:
   ```bash
   python3 scripts/generate_firewall_logs.py --count 1000 --interval 0.5
   ```

3. **Run the Plugin**:
   ```bash
   ./redpanda-connect-plugin-example -c config/firewall_anomaly_detector.yaml
   ```

### Production Setup

1. **Deploy with Docker**:
   ```bash
   docker build -t firewall-anomaly-detector .
   docker run -d \
     -v /path/to/models:/models \
     -e REDIS_PASSWORD=your_password \
     firewall-anomaly-detector
   ```

2. **Monitor with Prometheus**:
   ```yaml
   # prometheus.yml
   scrape_configs:
     - job_name: 'firewall-anomaly-detector'
       static_configs:
         - targets: ['localhost:4195']
   ```

## Testing

Run the test suite:

```bash
go test ./processor -v
```

### Manual Testing

1. **Generate Test Data**:
   ```bash
   python3 scripts/generate_firewall_logs.py --count 100 --anomaly-ratio 0.3
   ```

2. **Verify Redis Data**:
   ```bash
   redis-cli lrange firewall_logs 0 -1
   ```

3. **Check Kafka Topics**:
   ```bash
   kafka-console-consumer --bootstrap-server localhost:9092 --topic firewall-anomalies
   kafka-console-consumer --bootstrap-server localhost:9092 --topic firewall-normal
   ```

## Troubleshooting

### Common Issues

1. **Redis Connection Errors**:
   - Verify Redis is running and accessible
   - Check network connectivity and firewall rules
   - Validate Redis credentials

2. **No Anomalies Detected**:
   - Lower the `score_threshold` value
   - Increase the `window_seconds` for more stable patterns
   - Verify log data contains sufficient variation

3. **High Memory Usage**:
   - Reduce `window_seconds` to limit memory per window
   - Implement log rotation in Redis
   - Monitor window count and clear old windows

### Debug Mode

Enable debug logging:

```yaml
logger:
  level: DEBUG
  format: json
```

## Performance Considerations

- **Window Size**: Larger windows provide more stable patterns but use more memory
- **Processing Threads**: Increase pipeline threads for higher throughput
- **Redis Performance**: Use Redis clusters for high-volume deployments
- **Kafka Batching**: Configure appropriate batch sizes for optimal throughput

## Security Considerations

- Use TLS for Redis and Kafka connections in production
- Implement proper authentication and authorization
- Store sensitive configuration in environment variables
- Regularly rotate credentials and certificates
- Monitor access logs and audit trails

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This plugin is licensed under the Apache License 2.0. 