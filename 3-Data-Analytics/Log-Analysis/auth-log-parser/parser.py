#!/usr/bin/env python3
"""
Authentication Log Parser
Author: Giovanni Oliveira
Description: Comprehensive authentication log analysis tool for security monitoring
"""

import re
import sys
import json
import yaml
import argparse
import logging
import time
import geoip2.database
import requests
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
import sqlite3
import threading
import queue

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('auth_parser.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class LogPatterns:
    """Log pattern definitions for different systems and services"""
    
    # SSH authentication patterns
    SSH_FAILED_PASSWORD = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[\d+\]:\s+Failed password for (\w+) from ([\d.]+) port (\d+)'
    SSH_ACCEPTED_PASSWORD = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[\d+\]:\s+Accepted password for (\w+) from ([\d.]+) port (\d+)'
    SSH_INVALID_USER = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[\d+\]:\s+Invalid user (\w+) from ([\d.]+)'
    SSH_DISCONNECT = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[\d+\]:\s+Disconnected from ([\d.]+) port (\d+)'
    
    # Sudo patterns
    SUDO_COMMAND = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sudo:\s+(\w+) : TTY=(\S+) ; PWD=(\S+) ; USER=(\w+) ; COMMAND=(.+)'
    SUDO_FAILED = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sudo:\s+(\w+) : (\d+) incorrect password attempts'
    
    # System login patterns
    LOGIN_SUCCESS = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+login\[\d+\]:\s+LOGIN ON (\S+) BY (\w+)'
    LOGIN_FAILURE = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+login\[\d+\]:\s+FAILED LOGIN (\d+) FROM (\S+) FOR (\w+)'
    
    # Web server patterns (Apache/Nginx)
    APACHE_AUTH_FAIL = r'([\d.]+) - (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" 401 (\d+)'
    NGINX_AUTH_FAIL = r'([\d.]+) - (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" 401 (\d+) "([^"]*)" "([^"]*)"'

class ThreatIntelligence:
    """Threat intelligence integration for IP reputation checking"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour cache
        
    def check_ip_reputation(self, ip_address):
        """Check IP reputation across multiple sources"""
        # Check cache first
        cache_key = f"ip_rep_{ip_address}"
        if cache_key in self.cache:
            cached_time, result = self.cache[cache_key]
            if time.time() - cached_time < self.cache_ttl:
                return result
        
        reputation_data = {
            'ip': ip_address,
            'is_malicious': False,
            'confidence': 0,
            'sources': []
        }
        
        # Check AbuseIPDB if configured
        if self.config.get('abuseipdb', {}).get('enabled'):
            abuse_result = self._check_abuseipdb(ip_address)
            if abuse_result:
                reputation_data['sources'].append(abuse_result)
                if abuse_result.get('confidence_percentage', 0) > 75:
                    reputation_data['is_malicious'] = True
                    reputation_data['confidence'] = abuse_result['confidence_percentage']
        
        # Cache result
        self.cache[cache_key] = (time.time(), reputation_data)
        return reputation_data
    
    def _check_abuseipdb(self, ip_address):
        """Check IP against AbuseIPDB"""
        try:
            api_key = self.config.get('abuseipdb', {}).get('api_key')
            if not api_key:
                return None
                
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
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'source': 'AbuseIPDB',
                    'confidence_percentage': data.get('abuseConfidencePercentage', 0),
                    'usage_type': data.get('usageType', 'Unknown'),
                    'country_code': data.get('countryCode', 'Unknown')
                }
        except Exception as e:
            logger.error(f"AbuseIPDB check failed for {ip_address}: {e}")
        
        return None

class GeolocationAnalyzer:
    """Geographic analysis of IP addresses"""
    
    def __init__(self, geoip_db_path=None):
        self.geoip_reader = None
        if geoip_db_path and Path(geoip_db_path).exists():
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_db_path)
                logger.info(f"GeoIP database loaded: {geoip_db_path}")
            except Exception as e:
                logger.error(f"Failed to load GeoIP database: {e}")
    
    def get_location(self, ip_address):
        """Get geographic location for IP address"""
        if not self.geoip_reader:
            return None
        
        try:
            response = self.geoip_reader.city(ip_address)
            return {
                'country': response.country.iso_code,
                'country_name': response.country.name,
                'city': response.city.name,
                'latitude': float(response.location.latitude) if response.location.latitude else None,
                'longitude': float(response.location.longitude) if response.location.longitude else None,
                'timezone': str(response.location.time_zone) if response.location.time_zone else None
            }
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip_address}: {e}")
            return None

class BruteForceDetector:
    """Detect brute force authentication attacks"""
    
    def __init__(self, threshold=5, time_window=300):
        self.threshold = threshold
        self.time_window = time_window
        self.failed_attempts = defaultdict(list)
        self.alerts_sent = set()
    
    def analyze_event(self, event):
        """Analyze authentication event for brute force patterns"""
        if event.get('event_type') != 'auth_failure':
            return None
        
        source_ip = event.get('source_ip')
        if not source_ip:
            return None
        
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
        attempt_count = len(self.failed_attempts[source_ip])
        if attempt_count >= self.threshold:
            alert_key = f"brute_force_{source_ip}_{timestamp.date()}"
            if alert_key not in self.alerts_sent:
                self.alerts_sent.add(alert_key)
                return self._create_alert(source_ip, attempt_count, event)
        
        return None
    
    def _create_alert(self, source_ip, attempt_count, event):
        """Create brute force alert"""
        return {
            'type': 'brute_force',
            'severity': 'high',
            'source_ip': source_ip,
            'target_user': event.get('username', 'unknown'),
            'attempt_count': attempt_count,
            'time_window_seconds': self.time_window,
            'description': f'Brute force attack detected from {source_ip} with {attempt_count} failed attempts',
            'timestamp': event['timestamp'],
            'recommended_action': 'Block source IP and investigate user account',
            'event_details': event
        }

class CredentialStuffingDetector:
    """Detect credential stuffing attacks"""
    
    def __init__(self, threshold=10, time_window=600):
        self.threshold = threshold
        self.time_window = time_window
        self.login_attempts = defaultdict(lambda: defaultdict(list))
        self.alerts_sent = set()
    
    def analyze_event(self, event):
        """Analyze for credential stuffing patterns"""
        if event.get('event_type') != 'auth_failure':
            return None
        
        source_ip = event.get('source_ip')
        username = event.get('username')
        
        if not source_ip or not username:
            return None
        
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
            alert_key = f"credential_stuffing_{source_ip}_{timestamp.date()}"
            if alert_key not in self.alerts_sent:
                self.alerts_sent.add(alert_key)
                return self._create_alert(source_ip, unique_users, event)
        
        return None
    
    def _create_alert(self, source_ip, user_count, event):
        """Create credential stuffing alert"""
        return {
            'type': 'credential_stuffing',
            'severity': 'high',
            'source_ip': source_ip,
            'unique_usernames': user_count,
            'time_window_seconds': self.time_window,
            'description': f'Credential stuffing attack detected from {source_ip} targeting {user_count} different usernames',
            'timestamp': event['timestamp'],
            'recommended_action': 'Block source IP and review targeted user accounts',
            'event_details': event
        }

class GeographicAnomalyDetector:
    """Detect geographic anomalies in authentication"""
    
    def __init__(self, geolocation_analyzer, baseline_days=30):
        self.geo_analyzer = geolocation_analyzer
        self.baseline_days = baseline_days
        self.user_locations = defaultdict(set)
        self.baseline_established = defaultdict(bool)
        self.alerts_sent = set()
    
    def analyze_event(self, event):
        """Analyze for geographic anomalies"""
        if event.get('event_type') != 'auth_success':
            return None
        
        username = event.get('username')
        source_ip = event.get('source_ip')
        
        if not username or not source_ip:
            return None
        
        # Get geographic location
        location_data = self.geo_analyzer.get_location(source_ip)
        if not location_data or not location_data.get('country'):
            return None
        
        country = location_data['country']
        location_key = f"{country}:{location_data.get('city', 'Unknown')}"
        
        # Check if this is a new location for user
        if self.baseline_established[username]:
            if location_key not in self.user_locations[username]:
                alert_key = f"geo_anomaly_{username}_{location_key}_{event['timestamp'].date()}"
                if alert_key not in self.alerts_sent:
                    self.alerts_sent.add(alert_key)
                    return self._create_alert(username, source_ip, location_data, event)
        
        # Add to user's known locations
        self.user_locations[username].add(location_key)
        
        # For demo purposes, establish baseline immediately
        # In production, this would be based on actual time periods
        self.baseline_established[username] = True
        
        return None
    
    def _create_alert(self, username, source_ip, location_data, event):
        """Create geographic anomaly alert"""
        return {
            'type': 'geographic_anomaly',
            'severity': 'medium',
            'username': username,
            'source_ip': source_ip,
            'new_location': {
                'country': location_data.get('country'),
                'city': location_data.get('city'),
                'country_name': location_data.get('country_name')
            },
            'known_locations': list(self.user_locations[username]),
            'description': f'User {username} logged in from new location: {location_data.get("country_name", "Unknown")}',
            'timestamp': event['timestamp'],
            'recommended_action': 'Verify with user and consider additional authentication',
            'event_details': event
        }

class AuthLogParser:
    """Main authentication log parser class"""
    
    def __init__(self, config_file=None):
        self.config = self._load_config(config_file)
        self.patterns = LogPatterns()
        
        # Initialize components
        self.threat_intel = ThreatIntelligence(self.config.get('threat_intel', {}))
        
        geoip_db = self.config.get('geolocation', {}).get('database')
        self.geo_analyzer = GeolocationAnalyzer(geoip_db)
        
        # Initialize detectors
        bf_config = self.config.get('detection', {}).get('brute_force', {})
        self.brute_force_detector = BruteForceDetector(
            threshold=bf_config.get('threshold', 5),
            time_window=bf_config.get('time_window', 300)
        )
        
        cs_config = self.config.get('detection', {}).get('credential_stuffing', {})
        self.credential_stuffing_detector = CredentialStuffingDetector(
            threshold=cs_config.get('threshold', 10),
            time_window=cs_config.get('time_window', 600)
        )
        
        self.geo_anomaly_detector = GeographicAnomalyDetector(
            self.geo_analyzer,
            baseline_days=self.config.get('detection', {}).get('geographic_anomaly', {}).get('baseline_days', 30)
        )
        
        # Statistics
        self.stats = {
            'total_events': 0,
            'parsed_events': 0,
            'alerts_generated': 0,
            'start_time': datetime.now()
        }
    
    def _load_config(self, config_file):
        """Load configuration from YAML file"""
        if not config_file or not Path(config_file).exists():
            logger.warning("No config file provided or file not found, using defaults")
            return self._default_config()
        
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from {config_file}")
            return config
        except Exception as e:
            logger.error(f"Failed to load config file {config_file}: {e}")
            return self._default_config()
    
    def _default_config(self):
        """Return default configuration"""
        return {
            'detection': {
                'brute_force': {
                    'enabled': True,
                    'threshold': 5,
                    'time_window': 300
                },
                'credential_stuffing': {
                    'enabled': True,
                    'threshold': 10,
                    'time_window': 600
                },
                'geographic_anomaly': {
                    'enabled': True,
                    'baseline_days': 30
                }
            },
            'output': {
                'alerts': {
                    'enabled': True,
                    'formats': ['json']
                }
            }
        }
    
    def parse_log_line(self, line):
        """Parse a single log line and extract authentication events"""
        line = line.strip()
        if not line:
            return None
        
        self.stats['total_events'] += 1
        
        # Try SSH failed password
        match = re.search(self.patterns.SSH_FAILED_PASSWORD, line)
        if match:
            timestamp_str, hostname, username, source_ip, port = match.groups()
            return {
                'timestamp': self._parse_timestamp(timestamp_str),
                'hostname': hostname,
                'username': username,
                'source_ip': source_ip,
                'port': int(port),
                'event_type': 'auth_failure',
                'service': 'ssh',
                'raw_log': line
            }
        
        # Try SSH accepted password
        match = re.search(self.patterns.SSH_ACCEPTED_PASSWORD, line)
        if match:
            timestamp_str, hostname, username, source_ip, port = match.groups()
            return {
                'timestamp': self._parse_timestamp(timestamp_str),
                'hostname': hostname,
                'username': username,
                'source_ip': source_ip,
                'port': int(port),
                'event_type': 'auth_success',
                'service': 'ssh',
                'raw_log': line
            }
        
        # Try SSH invalid user
        match = re.search(self.patterns.SSH_INVALID_USER, line)
        if match:
            timestamp_str, hostname, username, source_ip = match.groups()
            return {
                'timestamp': self._parse_timestamp(timestamp_str),
                'hostname': hostname,
                'username': username,
                'source_ip': source_ip,
                'event_type': 'auth_failure',
                'service': 'ssh',
                'failure_reason': 'invalid_user',
                'raw_log': line
            }
        
        # Try sudo command
        match = re.search(self.patterns.SUDO_COMMAND, line)
        if match:
            timestamp_str, hostname, user, tty, pwd, target_user, command = match.groups()
            return {
                'timestamp': self._parse_timestamp(timestamp_str),
                'hostname': hostname,
                'username': user,
                'event_type': 'privilege_escalation',
                'service': 'sudo',
                'target_user': target_user,
                'command': command,
                'tty': tty,
                'working_directory': pwd,
                'raw_log': line
            }
        
        # Try sudo failed
        match = re.search(self.patterns.SUDO_FAILED, line)
        if match:
            timestamp_str, hostname, username, attempts = match.groups()
            return {
                'timestamp': self._parse_timestamp(timestamp_str),
                'hostname': hostname,
                'username': username,
                'event_type': 'auth_failure',
                'service': 'sudo',
                'failure_reason': 'incorrect_password',
                'attempt_count': int(attempts),
                'raw_log': line
            }
        
        return None
    
    def _parse_timestamp(self, timestamp_str):
        """Parse timestamp from log line"""
        try:
            # Handle syslog format (e.g., "Jan 15 14:30:25")
            current_year = datetime.now().year
            timestamp_with_year = f"{current_year} {timestamp_str}"
            return datetime.strptime(timestamp_with_year, "%Y %b %d %H:%M:%S")
        except ValueError:
            try:
                # Try ISO format
                return datetime.fromisoformat(timestamp_str)
            except ValueError:
                # Fallback to current time
                logger.warning(f"Could not parse timestamp: {timestamp_str}")
                return datetime.now()
    
    def analyze_event(self, event):
        """Analyze event for security threats"""
        if not event:
            return []
        
        self.stats['parsed_events'] += 1
        alerts = []
        
        # Enrich event with geographic data
        if event.get('source_ip'):
            location_data = self.geo_analyzer.get_location(event['source_ip'])
            if location_data:
                event.update(location_data)
            
            # Check threat intelligence
            threat_data = self.threat_intel.check_ip_reputation(event['source_ip'])
            if threat_data:
                event['threat_intel'] = threat_data
                
                # Generate alert for known malicious IPs
                if threat_data.get('is_malicious'):
                    alerts.append({
                        'type': 'malicious_ip',
                        'severity': 'critical',
                        'source_ip': event['source_ip'],
                        'threat_confidence': threat_data.get('confidence', 0),
                        'threat_sources': threat_data.get('sources', []),
                        'description': f'Authentication attempt from known malicious IP: {event["source_ip"]}',
                        'timestamp': event['timestamp'],
                        'recommended_action': 'Block IP immediately and investigate',
                        'event_details': event
                    })
        
        # Run detection algorithms
        if self.config.get('detection', {}).get('brute_force', {}).get('enabled', True):
            bf_alert = self.brute_force_detector.analyze_event(event)
            if bf_alert:
                alerts.append(bf_alert)
        
        if self.config.get('detection', {}).get('credential_stuffing', {}).get('enabled', True):
            cs_alert = self.credential_stuffing_detector.analyze_event(event)
            if cs_alert:
                alerts.append(cs_alert)
        
        if self.config.get('detection', {}).get('geographic_anomaly', {}).get('enabled', True):
            geo_alert = self.geo_anomaly_detector.analyze_event(event)
            if geo_alert:
                alerts.append(geo_alert)
        
        self.stats['alerts_generated'] += len(alerts)
        return alerts
    
    def parse_file(self, file_path, start_time=None, end_time=None):
        """Parse authentication events from log file"""
        events = []
        alerts = []
        
        logger.info(f"Parsing log file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        event = self.parse_log_line(line)
                        if event:
                            # Filter by time range if specified
                            if start_time and event['timestamp'] < start_time:
                                continue
                            if end_time and event['timestamp'] > end_time:
                                continue
                            
                            events.append(event)
                            
                            # Analyze for threats
                            event_alerts = self.analyze_event(event)
                            alerts.extend(event_alerts)
                    
                    except Exception as e:
                        logger.error(f"Error processing line {line_num}: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return [], []
        
        logger.info(f"Parsed {len(events)} events, generated {len(alerts)} alerts")
        return events, alerts
    
    def monitor_realtime(self, file_path, callback=None):
        """Monitor log file in real-time"""
        logger.info(f"Starting real-time monitoring of {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                # Seek to end of file
                f.seek(0, 2)
                
                while True:
                    line = f.readline()
                    if line:
                        event = self.parse_log_line(line)
                        if event:
                            alerts = self.analyze_event(event)
                            
                            if callback:
                                callback(event, alerts)
                            
                            # Print alerts to console
                            for alert in alerts:
                                self._print_alert(alert)
                    else:
                        time.sleep(0.1)
        
        except KeyboardInterrupt:
            logger.info("Real-time monitoring stopped by user")
        except Exception as e:
            logger.error(f"Error in real-time monitoring: {e}")
    
    def _print_alert(self, alert):
        """Print alert to console with formatting"""
        severity_colors = {
            'critical': '\033[91m',  # Red
            'high': '\033[93m',      # Yellow
            'medium': '\033[94m',    # Blue
            'low': '\033[92m'        # Green
        }
        
        reset_color = '\033[0m'
        color = severity_colors.get(alert['severity'], '')
        
        print(f"\n{color}🚨 SECURITY ALERT 🚨{reset_color}")
        print(f"Type: {alert['type']}")
        print(f"Severity: {color}{alert['severity'].upper()}{reset_color}")
        print(f"Description: {alert['description']}")
        print(f"Timestamp: {alert['timestamp']}")
        
        if alert.get('source_ip'):
            print(f"Source IP: {alert['source_ip']}")
        if alert.get('username'):
            print(f"Username: {alert['username']}")
        if alert.get('recommended_action'):
            print(f"Recommended Action: {alert['recommended_action']}")
        
        print("-" * 50)
    
    def generate_report(self, events, alerts, output_format='json'):
        """Generate analysis report"""
        report = {
            'generation_time': datetime.now().isoformat(),
            'analysis_period': {
                'start': min(e['timestamp'] for e in events).isoformat() if events else None,
                'end': max(e['timestamp'] for e in events).isoformat() if events else None
            },
            'statistics': {
                'total_events': len(events),
                'total_alerts': len(alerts),
                'alert_breakdown': Counter(alert['type'] for alert in alerts),
                'severity_breakdown': Counter(alert['severity'] for alert in alerts),
                'top_source_ips': Counter(event.get('source_ip') for event in events if event.get('source_ip')).most_common(10),
                'top_usernames': Counter(event.get('username') for event in events if event.get('username')).most_common(10),
                'service_breakdown': Counter(event.get('service') for event in events if event.get('service')),
                'event_type_breakdown': Counter(event.get('event_type') for event in events if event.get('event_type'))
            },
            'alerts': alerts,
            'parser_stats': self.stats
        }
        
        if output_format == 'json':
            return json.dumps(report, indent=2, default=str)
        elif output_format == 'summary':
            return self._generate_summary_report(report)
        else:
            return report
    
    def _generate_summary_report(self, report):
        """Generate human-readable summary report"""
        stats = report['statistics']
        
        summary = f"""
AUTHENTICATION LOG ANALYSIS SUMMARY
===================================

Analysis Period: {report['analysis_period']['start']} to {report['analysis_period']['end']}
Generated: {report['generation_time']}

OVERVIEW
--------
Total Events Processed: {stats['total_events']}
Security Alerts Generated: {stats['total_alerts']}

ALERT BREAKDOWN
---------------
"""
        
        for alert_type, count in stats['alert_breakdown'].items():
            summary += f"{alert_type.replace('_', ' ').title()}: {count}\n"
        
        summary += "\nSEVERITY BREAKDOWN\n------------------\n"
        for severity, count in stats['severity_breakdown'].items():
            summary += f"{severity.upper()}: {count}\n"
        
        summary += "\nTOP SOURCE IPs\n--------------\n"
        for ip, count in stats['top_source_ips']:
            summary += f"{ip}: {count} events\n"
        
        summary += "\nTOP USERNAMES\n-------------\n"
        for username, count in stats['top_usernames']:
            summary += f"{username}: {count} events\n"
        
        if stats['total_alerts'] > 0:
            summary += "\nRECOMMENDATIONS\n---------------\n"
            summary += "1. Review and investigate all high and critical severity alerts\n"
            summary += "2. Consider blocking IPs with multiple failed authentication attempts\n"
            summary += "3. Verify unusual geographic login patterns with users\n"
            summary += "4. Implement additional monitoring for frequently targeted accounts\n"
        
        return summary

def main():
    """Main function with command-line interface"""
    parser = argparse.ArgumentParser(description="Authentication Log Parser and Security Analyzer")
    
    parser.add_argument('--input', '-i', required=True, help='Input log file path')
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--format', '-f', choices=['json', 'summary'], default='summary', help='Output format')
    parser.add_argument('--follow', action='store_true', help='Follow log file for real-time monitoring')
    parser.add_argument('--start-time', help='Start time filter (YYYY-MM-DD HH:MM:SS)')
    parser.add_argument('--end-time', help='End time filter (YYYY-MM-DD HH:MM:SS)')
    parser.add_argument('--filter-ip', help='Filter events by source IP')
    parser.add_argument('--filter-user', help='Filter events by username')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize parser
    auth_parser = AuthLogParser(args.config)
    
    # Parse time filters
    start_time = None
    end_time = None
    
    if args.start_time:
        try:
            start_time = datetime.strptime(args.start_time, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            logger.error("Invalid start time format. Use YYYY-MM-DD HH:MM:SS")
            sys.exit(1)
    
    if args.end_time:
        try:
            end_time = datetime.strptime(args.end_time, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            logger.error("Invalid end time format. Use YYYY-MM-DD HH:MM:SS")
            sys.exit(1)
    
    if args.follow:
        # Real-time monitoring
        def alert_callback(event, alerts):
            for alert in alerts:
                auth_parser._print_alert(alert)
        
        auth_parser.monitor_realtime(args.input, callback=alert_callback)
    else:
        # Parse file
        events, alerts = auth_parser.parse_file(args.input, start_time, end_time)
        
        # Apply filters
        if args.filter_ip:
            events = [e for e in events if e.get('source_ip') == args.filter_ip]
            alerts = [a for a in alerts if a.get('source_ip') == args.filter_ip]
        
        if args.filter_user:
            events = [e for e in events if e.get('username') == args.filter_user]
            alerts = [a for a in alerts if a.get('username') == args.filter_user]
        
        # Generate report
        report = auth_parser.generate_report(events, alerts, args.format)
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            logger.info(f"Report saved to {args.output}")
        else:
            print(report)
        
        # Print summary to stderr
        if alerts:
            print(f"\n🚨 {len(alerts)} security alerts generated!", file=sys.stderr)
            critical_alerts = [a for a in alerts if a['severity'] == 'critical']
            if critical_alerts:
                print(f"⚠️  {len(critical_alerts)} CRITICAL alerts require immediate attention!", file=sys.stderr)

if __name__ == '__main__':
    main()