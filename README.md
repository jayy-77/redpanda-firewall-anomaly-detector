# 🔥 Redpanda Firewall Anomaly Detector

[![Go Version](https://img.shields.io/badge/Go-1.22+-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](Dockerfile)
[![Tests](https://img.shields.io/badge/Tests-Passing-green.svg)](processor/firewall_anomaly_detector_test.go)

A **production-ready** Redpanda Connect (Benthos) processor plugin that detects anomalies in firewall logs using machine learning and sliding time windows. Perfect for real-time security monitoring and threat detection.

> **New in v0.2**: full MLE stack — pluggable scorer interface (heuristic / HTTP / ONNX), Python `model_server` (FastAPI + sklearn), training pipeline mirroring the Go feature schema, online PSI drift detector, Prometheus + Grafana observability. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## 🎯 Features

### 🔍 **Advanced Anomaly Detection**
- **Sliding Time Windows**: Configurable time windows (default: 60 seconds) for each log source
- **7 Statistical Features**: Mean, std dev, max, min, percent change, unique IPs, peak-to-mean ratio
- **Pluggable Scorer**: `heuristic` (default), `http` (Python model server), or `onnx` (in-process)
- **ML Model Integration**: Isolation Forest, One-Class SVM, LOF, and Autoencoder via `model_server`
- **Online Drift Detection**: per-feature PSI against rolling baseline reservoir
- **Train-Serve Symmetry**: `training/extract_features.py` reproduces the Go feature schema bit-for-bit
- **Configurable Thresholds**: Adjustable anomaly detection sensitivity

### 🛡️ **Multi-Vendor Support**
- **Fortinet Firewall** - Connection count monitoring
- **Palo Alto Networks** - Bytes sent/received analysis
- **Check Point** - Comprehensive traffic analysis
- **Cisco ASA** - Connection-based detection
- **Juniper SRX** - Network flow monitoring
- **Sophos Firewall** - Security event correlation

### 🚀 **Production Ready**
- **Redis Integration**: High-performance log ingestion
- **Kafka/Redpanda Routing**: Separate topics for anomalies and normal events
- **Prometheus Metrics**: Built-in monitoring and alerting
- **Docker Support**: Containerized deployment
- **Thread-Safe**: Concurrent processing with mutex protection

## 🚀 Quick Start

### Prerequisites
```bash
# Required
- Go 1.22+
- Docker & Docker Compose
- Python 3.8+ (for test data generation)

# Optional
- Redis (for log ingestion)
- Kafka/Redpanda (for event routing)
```

### 1. Build & Run

```bash
# Clone the repository
git clone https://github.com/jaykumar/redpanda-firewall-anomaly-detector.git
cd redpanda-firewall-anomaly-detector

# Build the binary
go build -o firewall-anomaly-detector

# Run with basic configuration
./firewall-anomaly-detector -c config/firewall_anomaly_detector.yaml
```

### 2. Docker Deployment

```bash
# Build Docker image
docker build -t firewall-anomaly-detector .

# Run with Docker Compose (includes Redis & Kafka)
docker-compose up -d

# Check logs
docker-compose logs -f firewall-anomaly-detector
```

### 3. Generate Test Data

```bash
# Install Python dependencies
pip3 install redis

# Generate sample firewall logs
python3 scripts/generate_firewall_logs.py --count 1000 --interval 0.5 --anomaly-ratio 0.3
```

## 📋 Configuration

### Basic Configuration

```yaml
input:
  redis_list:
    url: "redis://localhost:6379"
    key: "firewall_logs"
    timeout: "5s"

pipeline:
  threads: 1
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

output:
  kafka:
    addresses: ["localhost:9092"]
    topic: "${! meta(\"topic\")}"
    key: "${! json(\"log_source\")}"
```

### Advanced Configuration

```yaml
pipeline:
  processors:
  - firewall_anomaly_detector:
      window_seconds: 300  # 5 minutes for stable patterns
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

## 📊 Input/Output Formats

### Input Log Format (JSON)

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

### Output Format (JSON)

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

## 🧪 Testing

### Unit Tests

```bash
# Run all tests
go test ./processor -v

# Test coverage
go test ./processor -cover
```

### Integration Tests

```bash
# Start services
docker-compose up -d

# Generate test data
python3 scripts/generate_firewall_logs.py --count 1000 --interval 0.5

# Run the detector
./firewall-anomaly-detector -c config/firewall_anomaly_detector_stdout.yaml
```

## 📈 Monitoring & Metrics

The plugin provides the following Prometheus metrics:

- `processed_logs`: Counter of processed log entries
- `anomalies_detected`: Counter of detected anomalies
- `windows_created`: Counter of created time windows

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'firewall-anomaly-detector'
    static_configs:
      - targets: ['localhost:4195']
```

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Firewall      │    │   Redis List     │    │   Anomaly       │
│   Logs          │───▶│   (firewall_logs) │───▶│   Detector      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                          │
                                                          ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Kafka/        │    │   Normal Events  │    │   Anomalous     │
│   Redpanda      │◀───│   Topic          │◀───│   Events Topic  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 📦 Project Structure

```
redpanda-firewall-anomaly-detector/
├── processor/                           # Core plugin implementation
│   ├── firewall_anomaly_detector.go    # Main processor (795 lines)
│   └── firewall_anomaly_detector_test.go # Comprehensive tests (221 lines)
├── config/                             # Configuration examples
│   ├── firewall_anomaly_detector.yaml  # Basic configuration
│   ├── firewall_anomaly_detector_advanced.yaml # Advanced setup
│   └── firewall_anomaly_detector_stdout.yaml # Testing configuration
├── scripts/                            # Test utilities
│   └── generate_firewall_logs.py       # Sample data generator
├── docs/                               # Documentation
│   └── firewall_anomaly_detector.md    # Complete API documentation
├── docker-compose.yml                  # Development environment
├── Dockerfile                          # Production container
├── main.go                             # Application entry point
└── README.md                           # This file
```

## 🔧 Development

### Prerequisites

```bash
# Install Go dependencies
go mod download

# Install Python dependencies
pip3 install redis
```

### Building

```bash
# Build for local development
go build -o firewall-anomaly-detector

# Build for production
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o firewall-anomaly-detector .

# Build Docker image
docker build -t firewall-anomaly-detector .
```

### Testing

```bash
# Run unit tests
go test ./processor -v

# Run with race detection
go test -race ./processor

# Generate test coverage
go test -coverprofile=coverage.out ./processor
go tool cover -html=coverage.out
```

## 🚀 Deployment

### Production Deployment

```bash
# 1. Build production image
docker build -t firewall-anomaly-detector:latest .

# 2. Deploy with Docker Compose
docker-compose -f docker-compose.prod.yml up -d

# 3. Monitor logs
docker-compose logs -f firewall-anomaly-detector

# 4. Check metrics
curl http://localhost:4195/metrics
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: firewall-anomaly-detector
spec:
  replicas: 3
  selector:
    matchLabels:
      app: firewall-anomaly-detector
  template:
    metadata:
      labels:
        app: firewall-anomaly-detector
    spec:
      containers:
      - name: firewall-anomaly-detector
        image: firewall-anomaly-detector:latest
        ports:
        - containerPort: 4195
        env:
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: redis-secret
              key: password
        volumeMounts:
        - name: models
          mountPath: /models
      volumes:
      - name: models
        persistentVolumeClaim:
          claimName: models-pvc
```

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Guidelines

- Write tests for new functionality
- Ensure all tests pass (`go test ./processor -v`)
- Follow Go coding standards
- Update documentation for new features
- Add examples for new configurations

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Redpanda Data** for the excellent Benthos framework
- **Gonum** for statistical calculations
- **Redis** for high-performance data storage
- **Apache Kafka** for event streaming

## 📞 Support

- 📧 **Email**: [prajapatijay1427@gmail.com]
- 📖 **Documentation**: [Complete Documentation](docs/firewall_anomaly_detector.md)

---

**⭐ Star this repository if you find it useful!**

**🔔 Watch for updates and new features!** 
