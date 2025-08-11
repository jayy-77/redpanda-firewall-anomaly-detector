# Redpanda Firewall Anomaly Detector

A production-ready Redpanda Connect (Benthos) processor plugin that detects anomalies in firewall logs using machine learning and sliding time windows.

## 🚀 Quick Start

### Prerequisites
- Go 1.22+
- Docker & Docker Compose
- Python 3.8+ (for test data generation)

### Build & Run

```bash
# Build the binary
go build -o firewall-anomaly-detector

# Run with configuration
./firewall-anomaly-detector -c config/firewall_anomaly_detector.yaml
```

### Docker

```bash
# Build Docker image
docker build -t firewall-anomaly-detector .

# Run with Docker Compose
docker-compose up -d
```

## 📖 Documentation

For comprehensive documentation, see:
- [📋 Complete Documentation](docs/firewall_anomaly_detector.md)
- [🚀 Quick Start Guide](README_FIREWALL_ANOMALY_DETECTOR.md)

## 🔧 Features

- **Sliding Time Windows**: Configurable time windows for each log source
- **Feature Extraction**: 7 statistical features (mean, std dev, max, min, percent change, unique IPs, peak-to-mean ratio)
- **ML Model Integration**: Ready for Isolation Forest and other ML models
- **Multi-Source Support**: Fortinet, Palo Alto, Checkpoint, Cisco, Juniper, Sophos
- **Redis Integration**: Reads logs from Redis lists
- **Kafka Routing**: Routes anomalies and normal events to separate topics
- **Metrics & Monitoring**: Built-in Prometheus metrics

## 🧪 Testing

```bash
# Run unit tests
go test ./processor -v

# Generate test data
python3 scripts/generate_firewall_logs.py --count 1000 --interval 0.5
```

## 📦 Project Structure

```
redpanda-firewall-anomaly-detector/
├── processor/                    # Main plugin implementation
│   ├── firewall_anomaly_detector.go
│   └── firewall_anomaly_detector_test.go
├── config/                      # Configuration examples
│   ├── firewall_anomaly_detector.yaml
│   └── firewall_anomaly_detector_advanced.yaml
├── scripts/                     # Test data generation
│   └── generate_firewall_logs.py
├── docs/                        # Documentation
│   └── firewall_anomaly_detector.md
├── docker-compose.yml           # Development environment
└── Dockerfile                   # Production container
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

This project is licensed under the Apache License 2.0.
