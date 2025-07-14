# Packet Sniffer with Scapy

A Python-based network packet analyzer using Scapy for real-time traffic monitoring and security analysis.

## Overview

This tool captures and analyzes network packets in real-time, providing insights into network traffic patterns and potential security threats. Built as part of cybersecurity learning and practical application of network analysis skills.

## Features

- **Real-time packet capture** with customizable filters
- **Protocol analysis** for TCP, UDP, ICMP, and more
- **Suspicious activity detection** based on traffic patterns
- **Export functionality** for further analysis
- **Comprehensive logging** with timestamps and metadata

## Installation

```bash
# Clone the repository
git clone https://github.com/giovannide/Digital-Forge.git
cd Digital-Forge/1-Cybersecurity/Network-Defense/packet-sniffer-scapy

# Install dependencies
pip install -r requirements.txt

# Run with administrative privileges
sudo python sniffer.py
```

## Usage

### Basic Packet Capture
```bash
sudo python sniffer.py --interface eth0 --count 100
```

### Protocol-Specific Filtering
```bash
sudo python sniffer.py --protocol tcp --port 80
```

### Suspicious Activity Detection
```bash
sudo python sniffer.py --detect-threats --output suspicious_traffic.log
```

## Configuration

Edit `config.json` to customize:
- Network interfaces to monitor
- Packet filters and protocols
- Threat detection rules
- Output formats and destinations

## Testing

```bash
# Run unit tests
python -m pytest test_sniffer.py -v

# Run integration tests
sudo python test_integration.py
```

## Security Considerations

- **Administrative privileges** required for packet capture
- **Network monitoring policies** must be followed
- **Data privacy** considerations for captured traffic
- **Legal compliance** with local network monitoring laws

## Learning Objectives

This project demonstrates:
- Network protocol understanding
- Python programming for cybersecurity
- Real-time data processing
- Security monitoring techniques
- Threat detection methodologies

## Related Coursework

Aligns with Google Cybersecurity Certificate:
- Course 3: Connect and Protect - Networks and Network Security
- Course 7: Automate Cybersecurity Tasks with Python

## Contributing

See [CONTRIBUTING.md](../../../docs/CONTRIBUTING.md) for guidelines on contributing to this project.

## License

MIT License - see [LICENSE](../../../LICENSE) for details.