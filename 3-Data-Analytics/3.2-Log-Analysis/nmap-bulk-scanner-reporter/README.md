# Nmap Bulk Scanner and Reporter

Network scanning and vulnerability assessment tool with comprehensive reporting capabilities for security auditing and monitoring.

## Overview

This tool automates network scanning using Nmap, processes the results, and generates detailed reports for security assessment and vulnerability management. It supports bulk scanning of multiple networks and provides customizable reporting formats.

## Features

- **Bulk Network Scanning** - Scan multiple networks and IP ranges
- **Service Enumeration** - Identify running services and versions
- **Vulnerability Detection** - Identify potential security issues
- **Custom Reporting** - Generate reports in multiple formats
- **Scheduling** - Automated scanning and reporting
- **Integration** - Connect with vulnerability management systems

## Installation

### Prerequisites
```bash
# Nmap
sudo apt-get install nmap

# Python 3.8+
python3 --version

# Required packages
pip install python-nmap xmltodict pandas matplotlib seaborn
```

### Quick Setup
```bash
# Clone repository
git clone https://github.com/giovannide/Digital-Forge.git
cd Digital-Forge/3-Data-Analytics/3.2-Log-Analysis/nmap-bulk-scanner-reporter

# Install dependencies
pip install -r requirements.txt

# Configure settings
cp config.yaml.example config.yaml
nano config.yaml

# Run scanner
python scanner.py --config config.yaml
```

## Usage

### Command Line Interface
```bash
# Basic scan of a single target
python scanner.py --target 192.168.1.0/24

# Scan multiple targets
python scanner.py --target 192.168.1.0/24 10.0.0.0/24

# Specify scan type
python scanner.py --target 192.168.1.0/24 --scan-type quick

# Generate specific report format
python scanner.py --target 192.168.1.0/24 --report html

# Comprehensive scan with all options
python scanner.py --target 192.168.1.0/24 --scan-type comprehensive --ports all --service-detection --output scan_results --format html,json,csv
```

### Configuration File
```yaml
# config.yaml example
scanner:
  threads: 4
  timeout: 300
  retries: 2

targets:
  networks:
    - 192.168.1.0/24
    - 10.0.0.0/24
  exclude:
    - 192.168.1.1
    - 10.0.0.1

scan_profiles:
  quick:
    ports: "top1000"
    timing: 4
    scripts: "default"
  
  comprehensive:
    ports: "1-65535"
    timing: 3
    scripts: "default,vuln"
  
  stealth:
    ports: "top100"
    timing: 2
    scripts: "default"
    options: "-sS"

reporting:
  formats:
    - html
    - json
    - csv
  output_dir: "reports"
  include_screenshots: false
  vulnerability_lookup: true
  
schedule:
  enabled: false
  frequency: "weekly"
  day: "sunday"
  time: "01:00"
```

## Scan Types

### Quick Scan
Fast scan of common ports for a quick overview of network services.

```bash
python scanner.py --target 192.168.1.0/24 --scan-type quick
```

### Comprehensive Scan
Detailed scan of all ports with service detection and basic vulnerability checks.

```bash
python scanner.py --target 192.168.1.0/24 --scan-type comprehensive
```

### Vulnerability Scan
Focused scan using Nmap NSE scripts to detect common vulnerabilities.

```bash
python scanner.py --target 192.168.1.0/24 --scan-type vuln
```

## Report Formats

### HTML Report
Interactive web-based report with charts, tables, and filtering capabilities.

### JSON/XML Export
Structured data format for integration with other security tools.

### CSV Export
Spreadsheet-compatible format for custom analysis and filtering.

### Executive Summary
High-level overview of findings for management reporting.

## Integration Options

### Vulnerability Databases
Lookup discovered services against known vulnerability databases.

### Ticketing Systems
Create tickets for identified vulnerabilities in systems like Jira or ServiceNow.

### SIEM Integration
Send scan results to SIEM systems for correlation and alerting.

## Security Considerations

- **Network Impact**: Scans can impact network performance
- **Authorization**: Always obtain proper authorization before scanning
- **False Positives**: Verify findings before taking action
- **Sensitive Data**: Handle scan results securely

## Contributing

See [CONTRIBUTING.md](../../../docs/CONTRIBUTING.md) for guidelines on contributing to this project.

## License

MIT License - see [LICENSE](../../../LICENSE) for details.

## Disclaimer

This tool is provided for legitimate security assessment purposes only. Always obtain proper authorization before scanning any networks or systems. The author is not responsible for misuse or unauthorized use of this tool.