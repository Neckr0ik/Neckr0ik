# Log Analysis Projects

Scripts and tools for parsing logs, analyzing security events, and generating comprehensive risk reports for security monitoring and incident investigation.

## Projects

### 🔐 auth-log-parser
Authentication log analysis tool for detecting suspicious login patterns, brute force attacks, and unauthorized access attempts.

**Key Features:**
- Real-time log monitoring and parsing
- Failed login attempt detection
- Geographic IP analysis and alerting
- User behavior pattern analysis
- Automated report generation

**Skills:** Python, Regular Expressions, Log Analysis, Pattern Recognition

---

### 🌐 nmap-bulk-scanner-reporter
Network scanning and vulnerability assessment tool with comprehensive reporting capabilities.

**Key Features:**
- Bulk network scanning automation
- Service enumeration and fingerprinting
- Vulnerability identification and scoring
- Custom reporting formats (HTML, JSON, CSV)
- Integration with vulnerability databases

**Skills:** Network Security, Nmap, Python, Vulnerability Assessment, Reporting

## Getting Started

Each project contains:
- `README.md` with detailed setup and usage instructions
- Python scripts with comprehensive documentation
- Sample log files and test data
- Configuration files and templates
- Output examples and report formats

## Prerequisites

- **Python 3.8+** for script execution
- **Log files** or network access for analysis
- **Regular expression knowledge** for pattern matching
- **Network security understanding** for vulnerability assessment

## Log Analysis Fundamentals

### Log Types and Sources

#### Authentication Logs
- **Linux**: `/var/log/auth.log`, `/var/log/secure`
- **Windows**: Security Event Log
- **Applications**: Custom application logs
- **Network Devices**: Syslog, SNMP logs

#### Security Event Categories
- **Authentication Events**: Login attempts, failures, lockouts
- **Authorization Events**: Permission changes, access denials
- **System Events**: Service starts/stops, configuration changes
- **Network Events**: Connection attempts, traffic anomalies

### Analysis Techniques

#### Pattern Recognition
```python
# Example: Detecting brute force attacks
import re
from collections import defaultdict

def detect_brute_force(log_lines, threshold=5):
    """Detect brute force attacks from auth logs"""
    failed_attempts = defaultdict(list)
    
    for line in log_lines:
        # Parse failed SSH login attempts
        match = re.search(r'Failed password for (\w+) from ([\d.]+)', line)
        if match:
            username, ip = match.groups()
            failed_attempts[ip].append(username)
    
    # Identify IPs with multiple failed attempts
    suspicious_ips = {
        ip: attempts for ip, attempts in failed_attempts.items()
        if len(attempts) >= threshold
    }
    
    return suspicious_ips
```

#### Statistical Analysis
```python
# Example: Login time analysis
import pandas as pd
from datetime import datetime

def analyze_login_patterns(auth_events):
    """Analyze login time patterns for anomaly detection"""
    df = pd.DataFrame(auth_events)
    df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
    
    # Calculate normal login hours
    normal_hours = df.groupby('hour').size()
    
    # Identify unusual login times
    unusual_logins = df[df['hour'].isin([0, 1, 2, 3, 4, 5, 22, 23])]
    
    return {
        'normal_pattern': normal_hours.to_dict(),
        'unusual_logins': unusual_logins.to_dict('records')
    }
```

### Security Monitoring

#### Real-time Analysis
- **Log streaming**: Continuous monitoring and processing
- **Alert generation**: Immediate notification of threats
- **Threshold monitoring**: Statistical anomaly detection
- **Correlation analysis**: Multi-source event correlation

#### Historical Analysis
- **Trend identification**: Long-term pattern analysis
- **Baseline establishment**: Normal behavior profiling
- **Forensic investigation**: Incident timeline reconstruction
- **Compliance reporting**: Regulatory requirement fulfillment

## Network Security Assessment

### Scanning Methodologies

#### Network Discovery
```bash
# Host discovery
nmap -sn 192.168.1.0/24

# Port scanning
nmap -sS -O 192.168.1.1

# Service enumeration
nmap -sV -sC 192.168.1.1
```

#### Vulnerability Assessment
```python
# Example: Automated vulnerability scanning
import subprocess
import json

def scan_network(target_range):
    """Perform comprehensive network scan"""
    
    # Host discovery
    hosts = discover_hosts(target_range)
    
    results = {}
    for host in hosts:
        # Port scan
        ports = scan_ports(host)
        
        # Service detection
        services = detect_services(host, ports)
        
        # Vulnerability check
        vulnerabilities = check_vulnerabilities(host, services)
        
        results[host] = {
            'ports': ports,
            'services': services,
            'vulnerabilities': vulnerabilities
        }
    
    return results
```

### Risk Assessment

#### Vulnerability Scoring
- **CVSS**: Common Vulnerability Scoring System
- **Risk prioritization**: Business impact assessment
- **Remediation planning**: Fix prioritization and timelines
- **Compliance mapping**: Regulatory requirement alignment

#### Reporting and Documentation
- **Executive summaries**: High-level risk overview
- **Technical details**: Detailed vulnerability information
- **Remediation guides**: Step-by-step fix instructions
- **Trend analysis**: Security posture improvement tracking

## Integration with Security Tools

### SIEM Integration
```python
# Example: Sending alerts to SIEM
import requests
import json

def send_to_siem(alert_data):
    """Send security alert to SIEM system"""
    
    siem_endpoint = "https://siem.company.com/api/alerts"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer YOUR_API_TOKEN'
    }
    
    payload = {
        'timestamp': alert_data['timestamp'],
        'severity': alert_data['severity'],
        'source': 'log-analyzer',
        'event_type': alert_data['event_type'],
        'details': alert_data['details']
    }
    
    response = requests.post(siem_endpoint, headers=headers, json=payload)
    return response.status_code == 200
```

### Ticketing System Integration
```python
# Example: Creating security tickets
def create_security_ticket(vulnerability_data):
    """Create ticket for vulnerability remediation"""
    
    ticket_data = {
        'title': f"Security Vulnerability: {vulnerability_data['cve_id']}",
        'description': vulnerability_data['description'],
        'severity': map_cvss_to_priority(vulnerability_data['cvss_score']),
        'category': 'Security',
        'assigned_team': 'Infrastructure',
        'due_date': calculate_due_date(vulnerability_data['cvss_score'])
    }
    
    # Submit to ticketing system
    return submit_ticket(ticket_data)
```

## Learning Objectives

### Technical Skills Development
- **Log parsing and analysis**: Extract meaningful information from logs
- **Pattern recognition**: Identify security threats and anomalies
- **Automation**: Streamline analysis and reporting processes
- **Tool integration**: Connect analysis tools with security infrastructure

### Security Knowledge Enhancement
- **Threat detection**: Recognize attack patterns and indicators
- **Incident investigation**: Reconstruct security events and timelines
- **Risk assessment**: Evaluate and prioritize security risks
- **Compliance**: Meet regulatory and audit requirements

## Real-World Applications

### Security Operations Center (SOC)
- **24/7 monitoring**: Continuous security event analysis
- **Incident triage**: Prioritize and escalate security events
- **Threat hunting**: Proactive search for security threats
- **Forensic analysis**: Detailed investigation of security incidents

### Compliance and Auditing
- **Regulatory reporting**: Meet compliance requirements
- **Audit preparation**: Document security controls and events
- **Risk management**: Identify and mitigate security risks
- **Policy enforcement**: Monitor adherence to security policies

### DevSecOps Integration
- **CI/CD security**: Integrate security analysis into development pipelines
- **Automated testing**: Continuous security validation
- **Vulnerability management**: Track and remediate security issues
- **Security metrics**: Measure and improve security posture