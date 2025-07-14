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

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                Authentication Log Parser                    │
│                                                             │
│  ┌─────────────────┐    ┌─────────────────┐               │
│  │   Log Sources   │    │   Processing    │               │
│  │                 │    │     Engine      │               │
│  │ • Auth.log      │───▶│                 │               │
│  │ • Secure.log    │    │ • Pattern Match │               │
│  │ • Event logs    │    │ • Threat Detect │               │
│  │ • App logs      │    │ • Geo Analysis  │               │
│  └─────────────────┘    └─────────────────┘               │
│                                   │                       │
│                                   ▼                       │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                Output & Alerts                          │ │
│  │                                                         │ │
│  │ • Real-time alerts  • Reports  • Dashboards           │ │
│  │ • SIEM integration  • Tickets  • Notifications        │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

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
cd Digital-Forge/3-Data-Analytics/Log-Analysis/auth-log-parser

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

### Docker Setup
```bash
# Build container
docker build -t auth-log-parser .

# Run with volume mount
docker run -v /var/log:/logs -v $(pwd)/config:/config auth-log-parser
```

## Configuration

### Main Configuration (`config.yaml`)
```yaml
# Input sources
input:
  log_files:
    - "/var/log/auth.log"
    - "/var/log/secure"
    - "/var/log/syslog"
  
  formats:
    - "syslog"
    - "json"
    - "csv"
  
  real_time: true
  tail_lines: 1000

# Detection rules
detection:
  brute_force:
    enabled: true
    threshold: 5
    time_window: 300  # 5 minutes
    
  credential_stuffing:
    enabled: true
    threshold: 10
    time_window: 600  # 10 minutes
    
  geographic_anomaly:
    enabled: true
    baseline_days: 30
    
  time_anomaly:
    enabled: true
    business_hours: "09:00-17:00"
    
  account_lockout:
    enabled: true
    threshold: 3

# Threat intelligence
threat_intel:
  enabled: true
  sources:
    - "abuseipdb"
    - "virustotal"
    - "otx"
  
  api_keys:
    abuseipdb: "YOUR_API_KEY"
    virustotal: "YOUR_API_KEY"

# Geographic analysis
geolocation:
  enabled: true
  database: "GeoLite2-City.mmdb"
  whitelist_countries: ["US", "CA", "GB"]

# Output configuration
output:
  alerts:
    enabled: true
    formats: ["json", "syslog"]
    destinations:
      - "file:///var/log/security-alerts.log"
      - "syslog://siem.company.com:514"
      - "webhook://slack.company.com/webhook"
  
  reports:
    enabled: true
    schedule: "daily"
    formats: ["html", "pdf", "json"]
    email_recipients:
      - "security@company.com"
      - "soc@company.com"

# Integration settings
integrations:
  siem:
    enabled: true
    type: "splunk"
    endpoint: "https://splunk.company.com:8088"
    token: "YOUR_HEC_TOKEN"
  
  ticketing:
    enabled: true
    type: "servicenow"
    endpoint: "https://company.service-now.com"
    username: "api_user"
    password: "api_password"
  
  notifications:
    slack:
      enabled: true
      webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    
    email:
      enabled: true
      smtp_server: "smtp.company.com"
      smtp_port: 587
      username: "alerts@company.com"
      password: "smtp_password"
```

### Log Format Patterns (`patterns.yaml`)
```yaml
# Syslog patterns
syslog:
  ssh_failed_password: 
    pattern: '(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[\d+\]:\s+Failed password for (\w+) from ([\d.]+) port (\d+)'
    fields: ['timestamp', 'hostname', 'username', 'source_ip', 'port']
    
  ssh_accepted:
    pattern: '(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[\d+\]:\s+Accepted password for (\w+) from ([\d.]+) port (\d+)'
    fields: ['timestamp', 'hostname', 'username', 'source_ip', 'port']
    
  sudo_command:
    pattern: '(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sudo:\s+(\w+) : TTY=(\S+) ; PWD=(\S+) ; USER=(\w+) ; COMMAND=(.+)'
    fields: ['timestamp', 'hostname', 'user', 'tty', 'pwd', 'target_user', 'command']

# Windows Event Log patterns
windows:
  logon_failure:
    event_id: 4625
    fields: ['timestamp', 'username', 'domain', 'source_ip', 'failure_reason']
    
  logon_success:
    event_id: 4624
    fields: ['timestamp', 'username', 'domain', 'source_ip', 'logon_type']
    
  account_lockout:
    event_id: 4740
    fields: ['timestamp', 'username', 'domain', 'source_workstation']

# Application-specific patterns
application:
  apache_auth:
    pattern: '([\d.]+) - (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+)'
    fields: ['source_ip', 'username', 'timestamp', 'method', 'url', 'protocol', 'status', 'size']
    
  nginx_auth:
    pattern: '([\d.]+) - (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"'
    fields: ['source_ip', 'username', 'timestamp', 'method', 'url', 'protocol', 'status', 'size', 'referrer', 'user_agent']
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

### Python API
```python
from auth_log_parser import AuthLogParser, DetectionEngine

# Initialize parser
parser = AuthLogParser(config_file='config.yaml')

# Parse log file
events = parser.parse_file('/var/log/auth.log')

# Real-time monitoring
def alert_handler(alert):
    print(f"ALERT: {alert['type']} - {alert['description']}")

parser.monitor_realtime('/var/log/auth.log', callback=alert_handler)

# Custom analysis
detection_engine = DetectionEngine()
threats = detection_engine.analyze_events(events)

# Generate reports
report = parser.generate_report(events, format='html')
```

## Detection Algorithms

### Brute Force Detection
```python
class BruteForceDetector:
    """Detect brute force authentication attacks"""
    
    def __init__(self, threshold=5, time_window=300):
        self.threshold = threshold
        self.time_window = time_window
        self.failed_attempts = defaultdict(list)
    
    def analyze_event(self, event):
        """Analyze authentication event for brute force patterns"""
        if event['event_type'] == 'auth_failure':
            source_ip = event['source_ip']
            timestamp = event['timestamp']
            
            # Add to failed attempts
            self.failed_attempts[source_ip].append(timestamp)
            
            # Clean old attempts outside time window
            cutoff_time = timestamp - timedelta(seconds=self.time_window)
            self.failed_attempts[source_ip] = [
                t for t in self.failed_attempts[source_ip] 
                if t > cutoff_time
            ]
            
            # Check if threshold exceeded
            if len(self.failed_attempts[source_ip]) >= self.threshold:
                return self.create_alert(source_ip, event)
        
        return None
    
    def create_alert(self, source_ip, event):
        """Create brute force alert"""
        return {
            'type': 'brute_force',
            'severity': 'high',
            'source_ip': source_ip,
            'target_user': event.get('username'),
            'attempt_count': len(self.failed_attempts[source_ip]),
            'time_window': self.time_window,
            'description': f'Brute force attack detected from {source_ip}',
            'timestamp': event['timestamp'],
            'recommended_action': 'Block source IP and investigate'
        }
```

### Credential Stuffing Detection
```python
class CredentialStuffingDetector:
    """Detect credential stuffing attacks"""
    
    def __init__(self, threshold=10, time_window=600):
        self.threshold = threshold
        self.time_window = time_window
        self.login_attempts = defaultdict(lambda: defaultdict(list))
    
    def analyze_event(self, event):
        """Analyze for credential stuffing patterns"""
        if event['event_type'] == 'auth_failure':
            source_ip = event['source_ip']
            username = event.get('username', 'unknown')
            timestamp = event['timestamp']
            
            # Track unique usernames per IP
            self.login_attempts[source_ip][username].append(timestamp)
            
            # Clean old attempts
            cutoff_time = timestamp - timedelta(seconds=self.time_window)
            for user in list(self.login_attempts[source_ip].keys()):
                self.login_attempts[source_ip][user] = [
                    t for t in self.login_attempts[source_ip][user]
                    if t > cutoff_time
                ]
                
                if not self.login_attempts[source_ip][user]:
                    del self.login_attempts[source_ip][user]
            
            # Check for multiple unique usernames
            unique_users = len(self.login_attempts[source_ip])
            if unique_users >= self.threshold:
                return self.create_alert(source_ip, unique_users, event)
        
        return None
    
    def create_alert(self, source_ip, user_count, event):
        """Create credential stuffing alert"""
        return {
            'type': 'credential_stuffing',
            'severity': 'high',
            'source_ip': source_ip,
            'unique_usernames': user_count,
            'time_window': self.time_window,
            'description': f'Credential stuffing attack detected from {source_ip}',
            'timestamp': event['timestamp'],
            'recommended_action': 'Block source IP and review user accounts'
        }
```

### Geographic Anomaly Detection
```python
class GeographicAnomalyDetector:
    """Detect geographic anomalies in authentication"""
    
    def __init__(self, geoip_db_path, baseline_days=30):
        import geoip2.database
        self.geoip_reader = geoip2.database.Reader(geoip_db_path)
        self.baseline_days = baseline_days
        self.user_locations = defaultdict(set)
        self.baseline_established = defaultdict(bool)
    
    def analyze_event(self, event):
        """Analyze for geographic anomalies"""
        if event['event_type'] == 'auth_success':
            username = event.get('username')
            source_ip = event['source_ip']
            timestamp = event['timestamp']
            
            if not username or not source_ip:
                return None
            
            try:
                # Get geographic location
                response = self.geoip_reader.city(source_ip)
                country = response.country.iso_code
                city = response.city.name
                location = f"{country}:{city}"
                
                # Check if this is a new location for user
                if self.baseline_established[username]:
                    if location not in self.user_locations[username]:
                        return self.create_alert(username, source_ip, location, event)
                
                # Add to user's known locations
                self.user_locations[username].add(location)
                
                # Mark baseline as established after baseline period
                if not self.baseline_established[username]:
                    # In real implementation, check if baseline_days have passed
                    self.baseline_established[username] = True
                
            except Exception as e:
                # Handle GeoIP lookup errors
                pass
        
        return None
    
    def create_alert(self, username, source_ip, location, event):
        """Create geographic anomaly alert"""
        return {
            'type': 'geographic_anomaly',
            'severity': 'medium',
            'username': username,
            'source_ip': source_ip,
            'new_location': location,
            'known_locations': list(self.user_locations[username]),
            'description': f'User {username} logged in from new location: {location}',
            'timestamp': event['timestamp'],
            'recommended_action': 'Verify with user and consider MFA requirement'
        }
```

### Time-based Anomaly Detection
```python
class TimeAnomalyDetector:
    """Detect time-based authentication anomalies"""
    
    def __init__(self, business_hours="09:00-17:00", timezone="UTC"):
        self.business_start, self.business_end = business_hours.split('-')
        self.timezone = timezone
        self.user_patterns = defaultdict(lambda: defaultdict(int))
    
    def analyze_event(self, event):
        """Analyze for time-based anomalies"""
        if event['event_type'] == 'auth_success':
            username = event.get('username')
            timestamp = event['timestamp']
            
            if not username:
                return None
            
            # Extract hour of day
            hour = timestamp.hour
            day_of_week = timestamp.weekday()  # 0=Monday, 6=Sunday
            
            # Check if outside business hours
            business_start_hour = int(self.business_start.split(':')[0])
            business_end_hour = int(self.business_end.split(':')[0])
            
            is_weekend = day_of_week >= 5  # Saturday or Sunday
            is_after_hours = hour < business_start_hour or hour >= business_end_hour
            
            if is_weekend or is_after_hours:
                # Update user pattern
                self.user_patterns[username][hour] += 1
                
                # Check if this is unusual for this user
                total_logins = sum(self.user_patterns[username].values())
                after_hours_logins = sum(
                    count for h, count in self.user_patterns[username].items()
                    if h < business_start_hour or h >= business_end_hour
                )
                
                # If less than 10% of logins are after hours, flag as anomaly
                if total_logins > 10 and after_hours_logins / total_logins < 0.1:
                    return self.create_alert(username, timestamp, event)
        
        return None
    
    def create_alert(self, username, timestamp, event):
        """Create time anomaly alert"""
        return {
            'type': 'time_anomaly',
            'severity': 'low',
            'username': username,
            'login_time': timestamp.strftime('%H:%M:%S'),
            'day_of_week': timestamp.strftime('%A'),
            'description': f'User {username} logged in outside normal hours',
            'timestamp': timestamp,
            'recommended_action': 'Review user activity and verify legitimacy'
        }
```

## Threat Intelligence Integration

### IP Reputation Checking
```python
class ThreatIntelligence:
    """Integrate with threat intelligence sources"""
    
    def __init__(self, config):
        self.config = config
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour
    
    def check_ip_reputation(self, ip_address):
        """Check IP reputation across multiple sources"""
        # Check cache first
        if ip_address in self.cache:
            cached_time, result = self.cache[ip_address]
            if time.time() - cached_time < self.cache_ttl:
                return result
        
        reputation_data = {
            'ip': ip_address,
            'is_malicious': False,
            'sources': [],
            'confidence': 0
        }
        
        # Check AbuseIPDB
        if self.config.get('abuseipdb', {}).get('enabled'):
            abuse_result = self.check_abuseipdb(ip_address)
            if abuse_result:
                reputation_data['sources'].append(abuse_result)
                if abuse_result['confidence_percentage'] > 75:
                    reputation_data['is_malicious'] = True
                    reputation_data['confidence'] = max(
                        reputation_data['confidence'], 
                        abuse_result['confidence_percentage']
                    )
        
        # Check VirusTotal
        if self.config.get('virustotal', {}).get('enabled'):
            vt_result = self.check_virustotal(ip_address)
            if vt_result:
                reputation_data['sources'].append(vt_result)
                if vt_result['malicious_count'] > 0:
                    reputation_data['is_malicious'] = True
                    reputation_data['confidence'] = max(
                        reputation_data['confidence'],
                        min(vt_result['malicious_count'] * 10, 100)
                    )
        
        # Cache result
        self.cache[ip_address] = (time.time(), reputation_data)
        
        return reputation_data
    
    def check_abuseipdb(self, ip_address):
        """Check IP against AbuseIPDB"""
        try:
            api_key = self.config['abuseipdb']['api_key']
            url = 'https://api.abuseipdb.com/api/v2/check'
            
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json()['data']
                return {
                    'source': 'AbuseIPDB',
                    'confidence_percentage': data['abuseConfidencePercentage'],
                    'is_public': data['isPublic'],
                    'usage_type': data['usageType'],
                    'country_code': data['countryCode']
                }
        
        except Exception as e:
            logger.error(f"AbuseIPDB check failed: {e}")
        
        return None
    
    def check_virustotal(self, ip_address):
        """Check IP against VirusTotal"""
        try:
            api_key = self.config['virustotal']['api_key']
            url = f'https://www.virustotal.com/vtapi/v2/ip-address/report'
            
            params = {
                'apikey': api_key,
                'ip': ip_address
            }
            
            response = requests.get(url, params=params)
            
            if response.status_code == 200:
                data = response.json()
                
                if data['response_code'] == 1:
                    detected_urls = data.get('detected_urls', [])
                    malicious_count = len([
                        url for url in detected_urls 
                        if url['positives'] > 0
                    ])
                    
                    return {
                        'source': 'VirusTotal',
                        'malicious_count': malicious_count,
                        'total_urls': len(detected_urls),
                        'country': data.get('country', 'Unknown')
                    }
        
        except Exception as e:
            logger.error(f"VirusTotal check failed: {e}")
        
        return None
```

## Reporting and Visualization

### HTML Report Generation
```python
class ReportGenerator:
    """Generate comprehensive security reports"""
    
    def __init__(self, template_dir='templates'):
        self.template_dir = template_dir
        
    def generate_html_report(self, analysis_results, output_file):
        """Generate HTML security report"""
        
        # Prepare report data
        report_data = {
            'generation_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': self.generate_summary(analysis_results),
            'alerts': analysis_results.get('alerts', []),
            'statistics': self.calculate_statistics(analysis_results),
            'charts': self.generate_charts(analysis_results),
            'recommendations': self.generate_recommendations(analysis_results)
        }
        
        # Load HTML template
        template = self.load_template('security_report.html')
        
        # Render report
        html_content = template.render(**report_data)
        
        # Save to file
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        return output_file
    
    def generate_summary(self, results):
        """Generate executive summary"""
        alerts = results.get('alerts', [])
        
        summary = {
            'total_events': results.get('total_events', 0),
            'total_alerts': len(alerts),
            'critical_alerts': len([a for a in alerts if a['severity'] == 'critical']),
            'high_alerts': len([a for a in alerts if a['severity'] == 'high']),
            'medium_alerts': len([a for a in alerts if a['severity'] == 'medium']),
            'low_alerts': len([a for a in alerts if a['severity'] == 'low']),
            'top_threat_types': self.get_top_threat_types(alerts),
            'top_source_ips': self.get_top_source_ips(alerts),
            'risk_score': self.calculate_risk_score(alerts)
        }
        
        return summary
    
    def calculate_statistics(self, results):
        """Calculate detailed statistics"""
        events = results.get('events', [])
        alerts = results.get('alerts', [])
        
        # Time-based analysis
        hourly_distribution = defaultdict(int)
        daily_distribution = defaultdict(int)
        
        for event in events:
            timestamp = event['timestamp']
            hourly_distribution[timestamp.hour] += 1
            daily_distribution[timestamp.date()] += 1
        
        # Geographic analysis
        country_distribution = defaultdict(int)
        for event in events:
            if 'country' in event:
                country_distribution[event['country']] += 1
        
        # User analysis
        user_activity = defaultdict(int)
        for event in events:
            if 'username' in event:
                user_activity[event['username']] += 1
        
        return {
            'hourly_distribution': dict(hourly_distribution),
            'daily_distribution': {str(k): v for k, v in daily_distribution.items()},
            'country_distribution': dict(country_distribution),
            'user_activity': dict(user_activity),
            'alert_trends': self.calculate_alert_trends(alerts)
        }
    
    def generate_charts(self, results):
        """Generate chart data for visualization"""
        import matplotlib.pyplot as plt
        import base64
        from io import BytesIO
        
        charts = {}
        
        # Alert severity distribution pie chart
        alerts = results.get('alerts', [])
        severity_counts = defaultdict(int)
        for alert in alerts:
            severity_counts[alert['severity']] += 1
        
        if severity_counts:
            fig, ax = plt.subplots(figsize=(8, 6))
            ax.pie(severity_counts.values(), labels=severity_counts.keys(), autopct='%1.1f%%')
            ax.set_title('Alert Severity Distribution')
            
            buffer = BytesIO()
            plt.savefig(buffer, format='png')
            buffer.seek(0)
            chart_data = base64.b64encode(buffer.getvalue()).decode()
            charts['severity_distribution'] = chart_data
            plt.close()
        
        # Timeline chart
        events = results.get('events', [])
        if events:
            timestamps = [event['timestamp'] for event in events]
            hourly_counts = defaultdict(int)
            
            for ts in timestamps:
                hourly_counts[ts.hour] += 1
            
            fig, ax = plt.subplots(figsize=(12, 6))
            hours = list(range(24))
            counts = [hourly_counts[h] for h in hours]
            
            ax.bar(hours, counts)
            ax.set_xlabel('Hour of Day')
            ax.set_ylabel('Event Count')
            ax.set_title('Authentication Events by Hour')
            ax.set_xticks(hours)
            
            buffer = BytesIO()
            plt.savefig(buffer, format='png')
            buffer.seek(0)
            chart_data = base64.b64encode(buffer.getvalue()).decode()
            charts['hourly_timeline'] = chart_data
            plt.close()
        
        return charts
```

## Integration Examples

### SIEM Integration (Splunk)
```python
class SplunkIntegration:
    """Send alerts and events to Splunk SIEM"""
    
    def __init__(self, hec_endpoint, hec_token):
        self.hec_endpoint = hec_endpoint
        self.hec_token = hec_token
        self.headers = {
            'Authorization': f'Splunk {hec_token}',
            'Content-Type': 'application/json'
        }
    
    def send_event(self, event_data):
        """Send event to Splunk HEC"""
        splunk_event = {
            'time': event_data['timestamp'].timestamp(),
            'source': 'auth-log-parser',
            'sourcetype': 'auth_events',
            'event': event_data
        }
        
        try:
            response = requests.post(
                f"{self.hec_endpoint}/services/collector/event",
                headers=self.headers,
                json=splunk_event
            )
            
            return response.status_code == 200
        
        except Exception as e:
            logger.error(f"Failed to send event to Splunk: {e}")
            return False
    
    def send_alert(self, alert_data):
        """Send alert to Splunk with notable event format"""
        notable_event = {
            'time': alert_data['timestamp'].timestamp(),
            'source': 'auth-log-parser',
            'sourcetype': 'notable_events',
            'event': {
                'rule_name': f"Auth Log Parser - {alert_data['type']}",
                'severity': alert_data['severity'],
                'description': alert_data['description'],
                'src_ip': alert_data.get('source_ip'),
                'user': alert_data.get('username'),
                'recommended_action': alert_data.get('recommended_action'),
                **alert_data
            }
        }
        
        return self.send_event(notable_event)
```

### Slack Notifications
```python
class SlackNotifier:
    """Send alerts to Slack channels"""
    
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url
    
    def send_alert(self, alert_data):
        """Send formatted alert to Slack"""
        
        # Color coding by severity
        colors = {
            'critical': '#FF0000',
            'high': '#FF8C00',
            'medium': '#FFD700',
            'low': '#90EE90'
        }
        
        color = colors.get(alert_data['severity'], '#808080')
        
        # Format message
        attachment = {
            'color': color,
            'title': f"🚨 Security Alert: {alert_data['type'].replace('_', ' ').title()}",
            'text': alert_data['description'],
            'fields': [
                {
                    'title': 'Severity',
                    'value': alert_data['severity'].upper(),
                    'short': True
                },
                {
                    'title': 'Source IP',
                    'value': alert_data.get('source_ip', 'N/A'),
                    'short': True
                },
                {
                    'title': 'Username',
                    'value': alert_data.get('username', 'N/A'),
                    'short': True
                },
                {
                    'title': 'Timestamp',
                    'value': alert_data['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    'short': True
                }
            ],
            'footer': 'Auth Log Parser',
            'ts': alert_data['timestamp'].timestamp()
        }
        
        if alert_data.get('recommended_action'):
            attachment['fields'].append({
                'title': 'Recommended Action',
                'value': alert_data['recommended_action'],
                'short': False
            })
        
        payload = {
            'username': 'Security Bot',
            'icon_emoji': ':shield:',
            'attachments': [attachment]
        }
        
        try:
            response = requests.post(self.webhook_url, json=payload)
            return response.status_code == 200
        
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False
```

## Performance and Scalability

### Optimized Log Processing
```python
class OptimizedLogProcessor:
    """High-performance log processing for large volumes"""
    
    def __init__(self, batch_size=1000, num_workers=4):
        self.batch_size = batch_size
        self.num_workers = num_workers
        self.event_queue = queue.Queue()
        self.result_queue = queue.Queue()
    
    def process_large_file(self, file_path):
        """Process large log files efficiently"""
        import multiprocessing
        from concurrent.futures import ThreadPoolExecutor
        
        # Start worker threads
        with ThreadPoolExecutor(max_workers=self.num_workers) as executor:
            # Submit processing tasks
            futures = []
            
            with open(file_path, 'r') as f:
                batch = []
                
                for line in f:
                    batch.append(line.strip())
                    
                    if len(batch) >= self.batch_size:
                        future = executor.submit(self.process_batch, batch)
                        futures.append(future)
                        batch = []
                
                # Process remaining lines
                if batch:
                    future = executor.submit(self.process_batch, batch)
                    futures.append(future)
            
            # Collect results
            all_results = []
            for future in futures:
                results = future.result()
                all_results.extend(results)
        
        return all_results
    
    def process_batch(self, lines):
        """Process a batch of log lines"""
        results = []
        
        for line in lines:
            try:
                event = self.parse_log_line(line)
                if event:
                    results.append(event)
            except Exception as e:
                logger.error(f"Error processing line: {e}")
        
        return results
    
    def parse_log_line(self, line):
        """Parse individual log line"""
        # Implementation depends on log format
        # This is a simplified example
        
        import re
        
        # SSH failed password pattern
        ssh_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[\d+\]:\s+Failed password for (\w+) from ([\d.]+)'
        
        match = re.search(ssh_pattern, line)
        if match:
            timestamp_str, hostname, username, source_ip = match.groups()
            
            return {
                'timestamp': self.parse_timestamp(timestamp_str),
                'hostname': hostname,
                'username': username,
                'source_ip': source_ip,
                'event_type': 'auth_failure',
                'service': 'ssh'
            }
        
        return None
```

## Contributing

See [CONTRIBUTING.md](../../../../docs/CONTRIBUTING.md) for guidelines on contributing to this project.

## License

MIT License - see [LICENSE](../../../../LICENSE) for details.

## Security Considerations

- **Log Privacy**: Ensure sensitive information is properly handled
- **API Keys**: Secure storage and rotation of threat intelligence API keys
- **Access Control**: Restrict access to log files and analysis results
- **Data Retention**: Implement appropriate log retention policies