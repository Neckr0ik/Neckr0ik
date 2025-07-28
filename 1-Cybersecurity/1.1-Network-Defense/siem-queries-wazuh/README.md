# SIEM Queries and Dashboards - Wazuh

SIEM implementation using Wazuh for centralized log management, security monitoring, and threat detection.

## Overview

This project demonstrates the implementation of a Security Information and Event Management (SIEM) system using Wazuh. It includes custom detection rules, queries, and dashboard configurations for comprehensive security monitoring.

## Features

- **Custom Detection Rules** for various attack patterns
- **Pre-configured Dashboards** for security monitoring
- **Alert Correlation** for incident detection
- **Threat Intelligence Integration** with external feeds
- **Compliance Reporting** for regulatory requirements

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Log Sources   │───▶│  Wazuh Manager  │───▶│   Kibana UI     │
│                 │    │                 │    │                 │
│ • Servers       │    │ • Rule Engine   │    │ • Dashboards    │
│ • Firewalls     │    │ • Correlation   │    │ • Alerts        │
│ • Applications  │    │ • Storage       │    │ • Reports       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Installation

### Prerequisites
- Ubuntu 20.04+ or CentOS 7+
- Minimum 4GB RAM, 2 CPU cores
- 50GB+ storage for log retention

### Quick Setup
```bash
# Download and install Wazuh
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a

# Import custom rules and dashboards
sudo cp rules/*.xml /var/ossec/etc/rules/
sudo cp dashboards/*.json /usr/share/kibana/
sudo systemctl restart wazuh-manager
```

## Configuration Files

### Custom Rules (`rules/`)
- `web_attacks.xml` - Web application attack detection
- `network_anomalies.xml` - Network-based threat detection
- `compliance_rules.xml` - Regulatory compliance monitoring
- `custom_alerts.xml` - Organization-specific alerts

### Dashboards (`dashboards/`)
- `security_overview.json` - Executive security dashboard
- `incident_response.json` - SOC analyst dashboard
- `compliance_report.json` - Compliance monitoring dashboard
- `threat_hunting.json` - Advanced threat hunting interface

### Queries (`queries/`)
- `failed_logins.json` - Failed authentication attempts
- `privilege_escalation.json` - Privilege escalation detection
- `data_exfiltration.json` - Data loss prevention queries
- `malware_detection.json` - Malware and suspicious file activity

## Usage Examples

### Basic Security Monitoring
```bash
# View real-time alerts
tail -f /var/ossec/logs/alerts/alerts.log

# Search for specific attack patterns
grep "SQL injection" /var/ossec/logs/alerts/alerts.log

# Generate compliance report
/var/ossec/bin/ossec-reportd -f compliance -d 30
```

### Advanced Threat Hunting
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-24h"}}},
        {"term": {"rule.level": {"value": 10}}}
      ]
    }
  }
}
```

## Alert Categories

### High Priority (Level 10+)
- **Authentication Failures** - Multiple failed login attempts
- **Privilege Escalation** - Unauthorized privilege changes
- **Data Exfiltration** - Large data transfers
- **Malware Detection** - Suspicious file activity

### Medium Priority (Level 7-9)
- **Network Anomalies** - Unusual network traffic
- **Configuration Changes** - System configuration modifications
- **Access Violations** - Unauthorized access attempts

### Low Priority (Level 1-6)
- **Informational Events** - Normal system activities
- **Compliance Logs** - Regulatory compliance events

## Dashboard Features

### Security Overview Dashboard
- Real-time threat landscape
- Top attack sources and targets
- Alert trend analysis
- System health monitoring

### Incident Response Dashboard
- Active incidents and their status
- Response time metrics
- Escalation procedures
- Communication templates

## Integration with Google Cybersecurity Certificate

This project aligns with:
- **Course 6**: Sound the Alarm - Detection and Response
- **SIEM concepts** and log analysis techniques
- **Incident response** procedures and documentation
- **Threat detection** methodologies

## Compliance Support

### Supported Frameworks
- **PCI DSS** - Payment card industry compliance
- **HIPAA** - Healthcare information protection
- **SOX** - Financial reporting compliance
- **GDPR** - Data protection regulation

### Reporting Features
- Automated compliance reports
- Audit trail documentation
- Risk assessment metrics
- Remediation tracking

## Troubleshooting

### Common Issues
1. **High Memory Usage**
   ```bash
   # Adjust Elasticsearch heap size
   sudo nano /etc/elasticsearch/jvm.options
   # Set -Xms2g and -Xmx2g for 4GB systems
   ```

2. **Missing Logs**
   ```bash
   # Check agent connectivity
   sudo /var/ossec/bin/agent_control -l
   # Restart agents if needed
   sudo systemctl restart wazuh-agent
   ```

3. **Dashboard Loading Issues**
   ```bash
   # Clear Kibana cache
   sudo rm -rf /usr/share/kibana/optimize/
   sudo systemctl restart kibana
   ```

## Performance Optimization

### Log Retention
- Configure log rotation policies
- Implement data lifecycle management
- Archive old logs to cold storage

### Resource Monitoring
- Monitor CPU and memory usage
- Optimize Elasticsearch indices
- Tune alert correlation rules

## Security Considerations

- **Secure Communication** - TLS encryption for all components
- **Access Control** - Role-based access to dashboards
- **Data Protection** - Encryption at rest and in transit
- **Audit Logging** - Complete audit trail of all activities

## Contributing

See [CONTRIBUTING.md](../../../docs/CONTRIBUTING.md) for guidelines on contributing to this project.

## License

MIT License - see [LICENSE](../../../LICENSE) for details.