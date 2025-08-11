#!/usr/bin/env python3
"""
Sample Firewall Log Generator

This script generates sample firewall logs and pushes them to Redis
for testing the firewall anomaly detector plugin.

Usage:
    python3 generate_firewall_logs.py [--count 100] [--interval 1] [--redis-host localhost] [--redis-port 6379]
"""

import json
import time
import random
import argparse
import redis
from datetime import datetime, timedelta
from typing import Dict, List

class FirewallLogGenerator:
    def __init__(self, redis_host: str = "localhost", redis_port: int = 6379, redis_db: int = 0):
        self.redis_client = redis.Redis(host=redis_host, port=redis_port, db=redis_db)
        self.log_sources = [
            "fortinet.firewall",
            "paloalto.firewall", 
            "checkpoint.firewall",
            "cisco.asa",
            "juniper.srx"
        ]
        
        # Generate realistic IP ranges
        self.source_ips = [f"192.168.{i}.{j}" for i in range(1, 255) for j in range(1, 255)]
        self.dest_ips = [f"10.{i}.{j}.{k}" for i in range(0, 255) for j in range(0, 255) for k in range(1, 255)]
        
    def generate_normal_log(self, log_source: str) -> Dict:
        """Generate a normal firewall log entry"""
        timestamp = datetime.now().isoformat() + "Z"
        
        # Normal traffic patterns
        connection_count = random.randint(1, 50)
        bytes_sent = random.randint(100, 10000)
        bytes_recv = random.randint(100, 10000)
        
        return {
            "timestamp": timestamp,
            "log_source": log_source,
            "source_ip": random.choice(self.source_ips),
            "dest_ip": random.choice(self.dest_ips),
            "connection_count": connection_count,
            "bytes_sent": bytes_sent,
            "bytes_recv": bytes_recv,
            "action": random.choice(["accept", "deny", "drop"]),
            "severity": random.choice(["low", "medium", "high"]),
            "raw": {
                "session_id": f"sess_{random.randint(10000, 99999)}",
                "protocol": random.choice(["tcp", "udp", "icmp"]),
                "src_port": random.randint(1024, 65535),
                "dst_port": random.randint(1, 65535)
            }
        }
    
    def generate_anomalous_log(self, log_source: str) -> Dict:
        """Generate an anomalous firewall log entry"""
        timestamp = datetime.now().isoformat() + "Z"
        
        # Anomalous traffic patterns - high connection count or bytes
        connection_count = random.randint(100, 1000)  # Much higher than normal
        bytes_sent = random.randint(50000, 500000)    # Much higher than normal
        bytes_recv = random.randint(50000, 500000)    # Much higher than normal
        
        return {
            "timestamp": timestamp,
            "log_source": log_source,
            "source_ip": random.choice(self.source_ips),
            "dest_ip": random.choice(self.dest_ips),
            "connection_count": connection_count,
            "bytes_sent": bytes_sent,
            "bytes_recv": bytes_recv,
            "action": random.choice(["accept", "deny", "drop"]),
            "severity": "high",
            "raw": {
                "session_id": f"sess_{random.randint(10000, 99999)}",
                "protocol": random.choice(["tcp", "udp", "icmp"]),
                "src_port": random.randint(1024, 65535),
                "dst_port": random.randint(1, 65535)
            }
        }
    
    def generate_burst_logs(self, log_source: str, burst_size: int = 10) -> List[Dict]:
        """Generate a burst of logs from the same source IP (potential DDoS)"""
        logs = []
        source_ip = random.choice(self.source_ips)
        
        for _ in range(burst_size):
            timestamp = datetime.now().isoformat() + "Z"
            
            log = {
                "timestamp": timestamp,
                "log_source": log_source,
                "source_ip": source_ip,  # Same source IP
                "dest_ip": random.choice(self.dest_ips),
                "connection_count": random.randint(50, 200),
                "bytes_sent": random.randint(10000, 50000),
                "bytes_recv": random.randint(10000, 50000),
                "action": "deny",
                "severity": "high",
                "raw": {
                    "session_id": f"sess_{random.randint(10000, 99999)}",
                    "protocol": random.choice(["tcp", "udp"]),
                    "src_port": random.randint(1024, 65535),
                    "dst_port": random.randint(1, 65535)
                }
            }
            logs.append(log)
        
        return logs
    
    def push_to_redis(self, logs: List[Dict], key: str = "firewall_logs"):
        """Push logs to Redis list"""
        for log in logs:
            log_json = json.dumps(log)
            self.redis_client.lpush(key, log_json)
    
    def generate_and_push(self, count: int, interval: float, anomaly_ratio: float = 0.1):
        """Generate and push logs to Redis"""
        print(f"Generating {count} logs with {anomaly_ratio*100}% anomaly ratio...")
        
        for i in range(count):
            # Determine if this should be an anomalous log
            if random.random() < anomaly_ratio:
                # Generate anomalous log
                log = self.generate_anomalous_log(random.choice(self.log_sources))
                print(f"[{i+1}/{count}] Generated ANOMALOUS log for {log['log_source']}")
            else:
                # Generate normal log
                log = self.generate_normal_log(random.choice(self.log_sources))
                print(f"[{i+1}/{count}] Generated normal log for {log['log_source']}")
            
            # Push to Redis
            self.push_to_redis([log])
            
            # Add some burst logs occasionally
            if random.random() < 0.05:  # 5% chance of burst
                burst_logs = self.generate_burst_logs(random.choice(self.log_sources), random.randint(5, 15))
                self.push_to_redis(burst_logs)
                print(f"Generated burst of {len(burst_logs)} logs")
            
            time.sleep(interval)
        
        print(f"Generated {count} logs successfully!")

def main():
    parser = argparse.ArgumentParser(description="Generate sample firewall logs for testing")
    parser.add_argument("--count", type=int, default=100, help="Number of logs to generate")
    parser.add_argument("--interval", type=float, default=1.0, help="Interval between logs in seconds")
    parser.add_argument("--redis-host", default="localhost", help="Redis host")
    parser.add_argument("--redis-port", type=int, default=6379, help="Redis port")
    parser.add_argument("--redis-db", type=int, default=0, help="Redis database")
    parser.add_argument("--anomaly-ratio", type=float, default=0.1, help="Ratio of anomalous logs (0.0-1.0)")
    
    args = parser.parse_args()
    
    try:
        generator = FirewallLogGenerator(
            redis_host=args.redis_host,
            redis_port=args.redis_port,
            redis_db=args.redis_db
        )
        
        generator.generate_and_push(
            count=args.count,
            interval=args.interval,
            anomaly_ratio=args.anomaly_ratio
        )
        
    except redis.ConnectionError:
        print(f"Error: Could not connect to Redis at {args.redis_host}:{args.redis_port}")
        print("Make sure Redis is running and accessible.")
        return 1
    except KeyboardInterrupt:
        print("\nStopped by user")
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 