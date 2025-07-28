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
- `README.md` with detailed setup instructions
- Source code with comprehensive documentation
- Sample log files and test data
- Configuration files and templates
- Output examples and report formats

## Prerequisites

- Python 3.8+ for data analysis scripts
- Log files or network access for analysis
- Regular expression knowledge for pattern matching
- Network security understanding for vulnerability assessment

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

## Skills Demonstrated

### Technical Skills
- **Python Programming**: Data processing and analysis
- **Regular Expressions**: Pattern matching and extraction
- **Data Visualization**: Report generation and visualization
- **Network Security**: Vulnerability assessment and analysis

### Security Skills
- **Threat Detection**: Identifying security threats and anomalies
- **Incident Investigation**: Analyzing security events and incidents
- **Risk Assessment**: Evaluating security risks and vulnerabilities
- **Compliance Monitoring**: Tracking regulatory compliance