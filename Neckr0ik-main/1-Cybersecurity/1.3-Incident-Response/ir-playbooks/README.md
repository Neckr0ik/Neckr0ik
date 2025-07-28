# Incident Response Playbooks

Comprehensive incident response procedures and documentation templates based on the NIST Cybersecurity Framework and industry best practices.

## Overview

This collection provides standardized incident response playbooks designed to guide security teams through effective incident handling. Each playbook follows a structured approach to ensure consistent, thorough, and legally compliant incident response.

## Features

- **NIST Framework Alignment** - Based on NIST SP 800-61 Rev. 2
- **Incident Classification** - Clear categorization and prioritization
- **Step-by-Step Procedures** - Detailed response workflows
- **Communication Templates** - Stakeholder notification formats
- **Evidence Handling** - Forensic preservation guidelines
- **Legal Compliance** - Regulatory reporting requirements

## Playbook Structure

### Core Components
1. **Incident Identification** - Detection and initial assessment
2. **Containment** - Immediate response and isolation
3. **Eradication** - Threat removal and system cleaning
4. **Recovery** - System restoration and monitoring
5. **Lessons Learned** - Post-incident analysis and improvement

## Available Playbooks

### 🦠 Malware Incident Response
**File**: `malware-incident-playbook.md`
**Scope**: Virus, ransomware, trojan, and other malicious software incidents

**Key Procedures:**
- Malware identification and classification
- System isolation and containment
- Forensic evidence collection
- Malware removal and system cleaning
- Recovery and hardening procedures

### 🔓 Data Breach Response
**File**: `data-breach-playbook.md`
**Scope**: Unauthorized access to sensitive data and information disclosure

**Key Procedures:**
- Breach scope assessment
- Legal and regulatory notification
- Customer and stakeholder communication
- Evidence preservation and analysis
- Remediation and prevention measures

### 🌐 Network Intrusion Response
**File**: `network-intrusion-playbook.md`
**Scope**: Unauthorized network access and lateral movement

**Key Procedures:**
- Network traffic analysis
- Compromised system identification
- Attack vector analysis
- Network segmentation and isolation
- Threat hunting and eradication

### 🚫 Denial of Service Response
**File**: `dos-incident-playbook.md`
**Scope**: Service availability attacks and resource exhaustion

**Key Procedures:**
- Attack pattern identification
- Traffic filtering and mitigation
- Service restoration procedures
- Capacity planning and scaling
- Prevention and monitoring enhancement

### 👤 Insider Threat Response
**File**: `insider-threat-playbook.md`
**Scope**: Internal security violations and policy breaches

**Key Procedures:**
- Behavioral analysis and investigation
- Access control and monitoring
- HR and legal coordination
- Evidence collection and documentation
- Disciplinary and corrective actions

## Quick Start Guide

### 1. Incident Detection
```bash
# Initial incident assessment
./assess-incident.sh --type <incident_type> --severity <level>

# Generate incident ID and documentation
./create-incident.sh --playbook <playbook_name>
```

### 2. Playbook Selection
Choose the appropriate playbook based on incident type:
- Malware → `malware-incident-playbook.md`
- Data breach → `data-breach-playbook.md`
- Network intrusion → `network-intrusion-playbook.md`
- DoS attack → `dos-incident-playbook.md`
- Insider threat → `insider-threat-playbook.md`

### 3. Response Execution
Follow the playbook procedures step-by-step:
1. **Immediate Response** (0-1 hour)
2. **Short-term Response** (1-24 hours)
3. **Extended Response** (1-7 days)
4. **Recovery Phase** (1-4 weeks)
5. **Post-Incident** (ongoing)

## Communication Templates

### Incident Notification Template
```
INCIDENT ALERT - [SEVERITY LEVEL]

Incident ID: INC-YYYY-MMDD-XXXX
Detection Time: [TIMESTAMP]
Incident Type: [CATEGORY]
Affected Systems: [SYSTEMS/SERVICES]
Impact Assessment: [HIGH/MEDIUM/LOW]

Initial Response Actions:
- [ACTION 1]
- [ACTION 2]
- [ACTION 3]

Next Update: [TIMESTAMP]
Incident Commander: [NAME]
Contact: [EMAIL/PHONE]
```

### Executive Summary Template
```
EXECUTIVE INCIDENT SUMMARY

Incident: [BRIEF DESCRIPTION]
Timeline: [START] - [END/ONGOING]
Business Impact: [DESCRIPTION]
Customer Impact: [YES/NO - DETAILS]
Data Involved: [TYPE AND VOLUME]
Root Cause: [PRELIMINARY/CONFIRMED]

Response Status:
✓ Containment: [COMPLETE/IN PROGRESS]
✓ Eradication: [COMPLETE/IN PROGRESS]
✓ Recovery: [COMPLETE/IN PROGRESS]

Estimated Resolution: [TIMESTAMP]
```

## Evidence Collection Guidelines

### Digital Evidence Handling
1. **Preservation Order**
   - Volatile memory (RAM)
   - Network connections
   - Running processes
   - Temporary files
   - Log files
   - Disk images

2. **Chain of Custody**
   - Document all evidence handling
   - Maintain chronological records
   - Secure storage and access controls
   - Legal admissibility requirements

3. **Forensic Tools**
   - Memory acquisition: `volatility`, `lime`
   - Disk imaging: `dd`, `dcfldd`, `ewfacquire`
   - Network analysis: `wireshark`, `tcpdump`
   - Log analysis: `grep`, `awk`, `splunk`

### Evidence Collection Script
```bash
#!/bin/bash
# Evidence collection automation

INCIDENT_ID="$1"
EVIDENCE_DIR="/var/evidence/${INCIDENT_ID}"

# Create evidence directory
mkdir -p "$EVIDENCE_DIR"

# Collect system information
uname -a > "$EVIDENCE_DIR/system_info.txt"
ps aux > "$EVIDENCE_DIR/processes.txt"
netstat -tulpn > "$EVIDENCE_DIR/network_connections.txt"

# Collect logs
cp /var/log/auth.log "$EVIDENCE_DIR/"
cp /var/log/syslog "$EVIDENCE_DIR/"
cp /var/log/apache2/access.log "$EVIDENCE_DIR/" 2>/dev/null

# Calculate checksums
find "$EVIDENCE_DIR" -type f -exec sha256sum {} \; > "$EVIDENCE_DIR/checksums.txt"

echo "Evidence collected in: $EVIDENCE_DIR"
```

## Incident Severity Classification

### Severity Levels

#### Critical (P1)
- **Impact**: Complete service outage or data breach
- **Response Time**: 15 minutes
- **Escalation**: Immediate executive notification
- **Examples**: Ransomware, major data breach, complete system compromise

#### High (P2)
- **Impact**: Significant service degradation or security compromise
- **Response Time**: 1 hour
- **Escalation**: Management notification within 2 hours
- **Examples**: Partial system compromise, targeted attacks, service disruption

#### Medium (P3)
- **Impact**: Limited service impact or potential security issue
- **Response Time**: 4 hours
- **Escalation**: Team lead notification
- **Examples**: Malware detection, policy violations, minor breaches

#### Low (P4)
- **Impact**: Minimal or no service impact
- **Response Time**: 24 hours
- **Escalation**: Standard reporting
- **Examples**: Failed login attempts, suspicious activity, informational alerts

## Legal and Regulatory Considerations

### Notification Requirements

#### GDPR (General Data Protection Regulation)
- **Timeline**: 72 hours to supervisory authority
- **Threshold**: High risk to rights and freedoms
- **Content**: Nature, categories, consequences, measures

#### HIPAA (Health Insurance Portability and Accountability Act)
- **Timeline**: 60 days to HHS, affected individuals
- **Threshold**: Unsecured PHI compromise
- **Content**: Description, investigation, mitigation

#### PCI DSS (Payment Card Industry Data Security Standard)
- **Timeline**: Immediately to card brands and acquirer
- **Threshold**: Suspected or confirmed compromise
- **Content**: Incident details, impact assessment, response actions

### Documentation Requirements
- Incident timeline and chronology
- Response actions and decisions
- Evidence collection and analysis
- Communication records
- Lessons learned and improvements

## Integration with Security Tools

### SIEM Integration
```python
# Example SIEM alert processing
import json
import requests

def process_siem_alert(alert_data):
    incident_type = classify_incident(alert_data)
    severity = assess_severity(alert_data)
    
    # Create incident record
    incident = create_incident(
        type=incident_type,
        severity=severity,
        source_data=alert_data
    )
    
    # Trigger appropriate playbook
    playbook = select_playbook(incident_type)
    execute_playbook(playbook, incident)
    
    return incident
```

### Ticketing System Integration
```python
# Example ServiceNow integration
def create_incident_ticket(incident_data):
    ticket_data = {
        'short_description': incident_data['title'],
        'description': incident_data['description'],
        'urgency': map_severity_to_urgency(incident_data['severity']),
        'category': 'Security',
        'subcategory': incident_data['type']
    }
    
    response = requests.post(
        f"{SERVICENOW_URL}/api/now/table/incident",
        json=ticket_data,
        auth=(USERNAME, PASSWORD)
    )
    
    return response.json()
```

## Metrics and KPIs

### Response Time Metrics
- **Mean Time to Detection (MTTD)**: Average time to detect incidents
- **Mean Time to Response (MTTR)**: Average time to begin response
- **Mean Time to Containment (MTTC)**: Average time to contain threats
- **Mean Time to Recovery (MTTRec)**: Average time to full recovery

### Quality Metrics
- **False Positive Rate**: Percentage of false alarms
- **Escalation Rate**: Percentage requiring escalation
- **Repeat Incident Rate**: Percentage of recurring incidents
- **Customer Impact**: Percentage affecting customers

### Compliance Metrics
- **Notification Timeliness**: Percentage meeting regulatory deadlines
- **Documentation Completeness**: Percentage with complete records
- **Training Completion**: Percentage of staff trained
- **Exercise Frequency**: Number of tabletop exercises conducted

## Training and Exercises

### Tabletop Exercises
Regular scenario-based discussions to test procedures:
- **Frequency**: Quarterly
- **Participants**: Incident response team, management
- **Scenarios**: Based on current threat landscape
- **Outcomes**: Procedure updates and training needs

### Simulation Exercises
Hands-on technical exercises in controlled environments:
- **Red Team Exercises**: Simulated attacks
- **Blue Team Response**: Detection and response
- **Purple Team Collaboration**: Joint improvement
- **Lessons Integration**: Playbook updates

## Continuous Improvement

### Post-Incident Review Process
1. **Timeline Reconstruction** - Detailed incident chronology
2. **Root Cause Analysis** - Technical and process failures
3. **Response Effectiveness** - What worked and what didn't
4. **Improvement Recommendations** - Specific actionable items
5. **Implementation Tracking** - Follow-up on recommendations

### Playbook Updates
- Regular review and revision cycles
- Integration of lessons learned
- Threat landscape adaptation
- Technology and tool updates
- Regulatory requirement changes

## Contributing

See [CONTRIBUTING.md](../../../../docs/CONTRIBUTING.md) for guidelines on contributing to this project.

## License

MIT License - see [LICENSE](../../../../LICENSE) for details.

## References

- [NIST SP 800-61 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS Incident Response Process](https://www.sans.org/white-papers/33901/)
- [ENISA Good Practice Guide](https://www.enisa.europa.eu/publications/good-practice-guide-for-incident-management)
- [ISO/IEC 27035](https://www.iso.org/standard/44379.html)