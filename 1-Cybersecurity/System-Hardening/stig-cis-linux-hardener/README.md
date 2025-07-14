# STIG/CIS Linux Hardener

Automated compliance hardening scripts implementing STIG (Security Technical Implementation Guide) and CIS (Center for Internet Security) benchmarks for Linux systems.

## Overview

This project provides automated security hardening scripts that implement industry-standard security configurations based on DISA STIG and CIS benchmarks. The scripts are designed to improve system security posture while maintaining operational functionality.

## Features

- **Automated Hardening** - One-click security configuration
- **Compliance Reporting** - Detailed audit reports and compliance status
- **Rollback Capability** - Safe reversal of security changes
- **Custom Policies** - Organization-specific security configurations
- **Multi-Distribution Support** - Ubuntu, CentOS, RHEL compatibility

## Supported Standards

### DISA STIG (Security Technical Implementation Guide)
- **Ubuntu 20.04 STIG V1R1** - DoD-approved security configurations
- **Red Hat Enterprise Linux 8 STIG V1R1** - Enterprise security standards
- **Application STIGs** - Apache, MySQL, SSH hardening

### CIS Benchmarks
- **CIS Ubuntu Linux 20.04 LTS Benchmark v1.1.0**
- **CIS Red Hat Enterprise Linux 8 Benchmark v1.0.0**
- **CIS Controls v8** - Implementation guidelines

## Installation

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y curl wget git

# RHEL/CentOS
sudo yum install -y curl wget git
```

### Quick Installation
```bash
# Clone the repository
git clone https://github.com/giovannide/Digital-Forge.git
cd Digital-Forge/1-Cybersecurity/System-Hardening/stig-cis-linux-hardener

# Make scripts executable
chmod +x *.sh

# Run initial assessment
sudo ./assess-compliance.sh
```

## Usage

### Basic Hardening
```bash
# Run complete hardening suite
sudo ./harden.sh

# Run specific category hardening
sudo ./harden.sh --category network
sudo ./harden.sh --category filesystem
sudo ./harden.sh --category authentication
```

### Assessment and Reporting
```bash
# Generate compliance report
sudo ./assess-compliance.sh --format html

# Check specific controls
sudo ./assess-compliance.sh --control "SV-238200r653787_rule"

# Generate executive summary
sudo ./assess-compliance.sh --summary
```

### Rollback Operations
```bash
# List available rollback points
sudo ./rollback.sh --list

# Rollback to specific point
sudo ./rollback.sh --restore 2024-01-15_14-30-00

# Rollback specific category
sudo ./rollback.sh --category network
```

## Hardening Categories

### 1. System Configuration
- Kernel parameter tuning
- Boot loader security
- File system configuration
- System service management

### 2. Network Security
- Firewall configuration
- Network parameter tuning
- Service port management
- Protocol security settings

### 3. Authentication & Access Control
- Password policy enforcement
- Account lockout policies
- Sudo configuration
- SSH hardening

### 4. Audit & Logging
- Audit daemon configuration
- Log retention policies
- Security event monitoring
- Compliance logging

### 5. File System Security
- Permission hardening
- Mount option security
- File integrity monitoring
- Backup and recovery

## Configuration Files

### Main Configuration (`config/hardening.conf`)
```bash
# Hardening configuration file
ENABLE_NETWORK_HARDENING=true
ENABLE_SSH_HARDENING=true
ENABLE_AUDIT_LOGGING=true
ENABLE_FILE_PERMISSIONS=true

# Compliance standards to apply
APPLY_STIG_CONTROLS=true
APPLY_CIS_CONTROLS=true

# Backup settings
CREATE_BACKUPS=true
BACKUP_LOCATION="/var/backups/hardening"

# Reporting settings
GENERATE_REPORTS=true
REPORT_FORMAT="html"
```

### Custom Policies (`config/custom-policies.conf`)
```bash
# Organization-specific security policies
ORG_PASSWORD_MIN_LENGTH=14
ORG_ACCOUNT_LOCKOUT_THRESHOLD=3
ORG_SESSION_TIMEOUT=900

# Custom firewall rules
CUSTOM_FIREWALL_RULES=(
    "allow from 10.0.0.0/8 to any port 22"
    "allow from 192.168.0.0/16 to any port 80"
)

# Additional audit rules
CUSTOM_AUDIT_RULES=(
    "-w /etc/passwd -p wa -k identity"
    "-w /etc/shadow -p wa -k identity"
)
```

## Script Components

### Core Scripts

#### `harden.sh` - Main Hardening Script
```bash
#!/bin/bash
# Main hardening script implementing STIG/CIS controls

# Usage: ./harden.sh [options]
# Options:
#   --category <category>  Apply specific category hardening
#   --dry-run             Show what would be changed without applying
#   --force               Skip confirmation prompts
#   --config <file>       Use custom configuration file
```

#### `assess-compliance.sh` - Compliance Assessment
```bash
#!/bin/bash
# Compliance assessment and reporting script

# Usage: ./assess-compliance.sh [options]
# Options:
#   --format <format>     Report format (html, json, xml, text)
#   --control <id>        Check specific control
#   --summary             Generate executive summary
#   --baseline            Create compliance baseline
```

#### `rollback.sh` - Configuration Rollback
```bash
#!/bin/bash
# Rollback hardening changes

# Usage: ./rollback.sh [options]
# Options:
#   --list                List available rollback points
#   --restore <point>     Restore to specific point
#   --category <cat>      Rollback specific category
#   --verify              Verify rollback integrity
```

### Supporting Scripts

#### `backup-system.sh` - System Backup
Creates comprehensive system backups before applying hardening changes.

#### `generate-report.sh` - Report Generation
Generates detailed compliance reports in multiple formats.

#### `validate-config.sh` - Configuration Validation
Validates system configuration against security benchmarks.

## Security Controls Implementation

### High Priority Controls (CAT I)

#### Network Security
```bash
# Disable unused network protocols
echo "install dccp /bin/true" >> /etc/modprobe.d/blacklist-rare-network.conf
echo "install sctp /bin/true" >> /etc/modprobe.d/blacklist-rare-network.conf
echo "install rds /bin/true" >> /etc/modprobe.d/blacklist-rare-network.conf
echo "install tipc /bin/true" >> /etc/modprobe.d/blacklist-rare-network.conf

# Configure kernel network parameters
cat >> /etc/sysctl.d/99-stig-network.conf << 'EOF'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
EOF
```

#### Authentication Security
```bash
# Configure password quality requirements
cat > /etc/security/pwquality.conf << 'EOF'
minlen = 15
minclass = 4
maxrepeat = 2
maxclassrepeat = 4
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 8
EOF

# Configure account lockout
cat >> /etc/pam.d/common-auth << 'EOF'
auth required pam_tally2.so deny=3 unlock_time=604800 onerr=fail
EOF
```

### Medium Priority Controls (CAT II)

#### File System Security
```bash
# Set secure file permissions
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group
chmod 640 /etc/gshadow

# Configure secure mount options
echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
echo "tmpfs /var/tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
```

#### Audit Configuration
```bash
# Configure comprehensive audit rules
cat > /etc/audit/rules.d/stig.rules << 'EOF'
# Delete all existing rules
-D

# Buffer size
-b 8192

# Failure mode
-f 1

# Monitor authentication events
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity

# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change

# Monitor network configuration
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale

# Monitor file access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access

# Make rules immutable
-e 2
EOF
```

## Compliance Reporting

### HTML Report Generation
```bash
# Generate comprehensive HTML report
sudo ./assess-compliance.sh --format html --output /var/www/html/compliance-report.html
```

### JSON API Integration
```bash
# Generate JSON report for API consumption
sudo ./assess-compliance.sh --format json --output compliance-data.json

# Example JSON structure:
{
  "assessment_date": "2024-01-15T14:30:00Z",
  "system_info": {
    "hostname": "secure-server",
    "os": "Ubuntu 20.04.3 LTS",
    "kernel": "5.4.0-91-generic"
  },
  "compliance_summary": {
    "total_controls": 245,
    "compliant": 198,
    "non_compliant": 32,
    "not_applicable": 15,
    "compliance_percentage": 80.8
  },
  "findings": [
    {
      "control_id": "SV-238200r653787_rule",
      "title": "Password minimum length",
      "status": "compliant",
      "severity": "medium"
    }
  ]
}
```

## Testing and Validation

### Automated Testing
```bash
# Run comprehensive test suite
./tests/run-tests.sh

# Test specific hardening category
./tests/test-network-hardening.sh

# Validate configuration integrity
./tests/validate-hardening.sh
```

### Manual Verification
```bash
# Check STIG compliance manually
sudo ./manual-checks/verify-stig-controls.sh

# Validate CIS benchmark compliance
sudo ./manual-checks/verify-cis-controls.sh

# Test system functionality after hardening
./tests/functional-tests.sh
```

## Troubleshooting

### Common Issues

1. **Service Startup Failures**
   ```bash
   # Check service status
   systemctl status <service-name>
   
   # Review hardening logs
   tail -f /var/log/hardening.log
   
   # Rollback specific service configuration
   ./rollback.sh --category services
   ```

2. **Network Connectivity Issues**
   ```bash
   # Check firewall rules
   iptables -L -n
   ufw status verbose
   
   # Verify network parameters
   sysctl net.ipv4.ip_forward
   
   # Rollback network hardening
   ./rollback.sh --category network
   ```

3. **Authentication Problems**
   ```bash
   # Check PAM configuration
   pam-auth-update --package
   
   # Verify password policies
   pwscore <<< "testpassword"
   
   # Reset authentication settings
   ./rollback.sh --category authentication
   ```

### Log Analysis
```bash
# Monitor hardening process
tail -f /var/log/hardening.log

# Check system logs for issues
journalctl -xe

# Review audit logs
ausearch -k identity
```

## Integration with CI/CD

### GitLab CI Example
```yaml
stages:
  - security-assessment
  - hardening
  - validation

security-assessment:
  stage: security-assessment
  script:
    - ./assess-compliance.sh --format json --output baseline.json
  artifacts:
    reports:
      junit: baseline.json

apply-hardening:
  stage: hardening
  script:
    - ./harden.sh --force --config production.conf
  only:
    - main

validate-hardening:
  stage: validation
  script:
    - ./assess-compliance.sh --format json --output final.json
    - ./tests/validate-hardening.sh
  artifacts:
    reports:
      junit: final.json
```

## Contributing

See [CONTRIBUTING.md](../../../../docs/CONTRIBUTING.md) for guidelines on contributing to this project.

## License

MIT License - see [LICENSE](../../../../LICENSE) for details.

## References

- [DISA STIG Library](https://public.cyber.mil/stigs/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [Ubuntu Security Guide](https://ubuntu.com/security/certifications/docs/usg)