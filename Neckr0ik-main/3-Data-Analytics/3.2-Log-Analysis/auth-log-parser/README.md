# Authentication Log Parser

Comprehensive authentication log analysis tool for detecting suspicious login patterns, brute force attacks, and unauthorized access attempts across multiple platforms and log formats.

## Overview

This tool provides automated analysis of authentication logs to identify security threats, generate alerts, and produce detailed reports for security monitoring and incident response. It supports multiple log formats and provides real-time monitoring capabilities.

## Features

- **Multi-format Support** - Linux, Windows, and application logs
- **Real-time Monitoring** - Continuous log analysis and alerting
- **Threat Detection** - Brute force, credential stuffing, and anomaly detection
- **Geographic Analysis** - IP geolocation and threat intelligence
- **Automated Reporting** - Customizable reports and dashboards
- **Integration Ready** - SIEM, ticketing, and notification systems

## Installation

### Prerequisites
```bash
# Python 3.8+
python3 --version

# Required system packages
sudo apt-get install geoip-bin geoip-database

# Python packages
pip install requests pandas matplotlib seaborn geoip2 maxminddb
```

### Quick Setup
```bash
# Clone repository
git clone https://github.com/giovannide/Digital-Forge.git
cd Digital-Forge/3-Data-Analytics/3.2-Log-Analysis/auth-log-parser

# Install dependencies
pip install -r requirements.txt

# Download GeoIP database
wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
gunzip GeoLite2-City.mmdb.gz

# Configure settings
cp config.yaml.example config.yaml
nano config.yaml

# Run parser
python parser.py --config config.yaml --input /var/log/auth.log
```

## Usage

### Command Line Interface
```bash
# Basic usage
python parser.py --input /var/log/auth.log

# Real-time monitoring
python parser.py --input /var/log/auth.log --follow

# Custom configuration
python parser.py --config custom_config.yaml --input /var/log/auth.log

# Multiple log files
python parser.py --input /var/log/auth.log /var/log/secure --output report.json

# Specific time range
python parser.py --input /var/log/auth.log --start "2024-01-01 00:00:00" --end "2024-01-31 23:59:59"

# Filter by IP or user
python parser.py --input /var/log/auth.log --filter-ip 192.168.1.100
python parser.py --input /var/log/auth.log --filter-user admin

# Generate specific reports
python parser.py --input /var/log/auth.log --report brute-force --format html
```

## Detection Capabilities

### Brute Force Detection
Identifies multiple failed login attempts from the same source IP address within a specified time window.

### Credential Stuffing Detection
Detects attempts to use multiple different usernames from the same source IP address, indicating potential credential stuffing attacks.

### Geographic Anomaly Detection
Identifies login attempts from unusual geographic locations based on user behavior patterns and baseline analysis.

### Time-based Anomaly Detection
Detects login attempts during unusual hours or days based on established user behavior patterns.

## Integration Options

### SIEM Integration
Supports sending alerts and events to SIEM systems like Splunk, ELK Stack, and others through various output formats and APIs.

### Notification Systems
Can send alerts to email, Slack, and other notification channels for real-time security monitoring.

### Ticketing Systems
Integrates with ticketing systems like ServiceNow and Jira for automated incident creation and tracking.

## Reporting Features

### HTML Reports
Generates comprehensive HTML reports with visualizations, statistics, and actionable insights.

### JSON/CSV Exports
Provides structured data exports for further analysis and integration with other tools.

### Executive Summaries
Creates high-level summaries for management and stakeholder reporting.

## Contributing

See [CONTRIBUTING.md](../../../docs/CONTRIBUTING.md) for guidelines on contributing to this project.

## License

MIT License - see [LICENSE](../../../LICENSE) for details.