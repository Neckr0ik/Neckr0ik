# Linux Basics Security Lab

Hands-on laboratory environment for learning Linux security fundamentals, file permissions, user management, and system hardening techniques.

## Overview

This lab provides a safe, isolated environment for practicing essential Linux security skills. Using Vagrant and VirtualBox, you'll work through practical exercises that build foundational cybersecurity knowledge.

## Learning Objectives

By completing this lab, you will:
- Understand Linux file permissions and access controls
- Master user and group management
- Configure basic network security settings
- Implement system monitoring and logging
- Apply security best practices for Linux systems

## Lab Environment

### Architecture
```
┌─────────────────────────────────────────┐
│              Host System                │
│  ┌─────────────────────────────────────┐ │
│  │         VirtualBox VM               │ │
│  │  ┌─────────────────────────────────┐ │ │
│  │  │      Ubuntu 20.04 LTS          │ │ │
│  │  │                                 │ │ │
│  │  │  • Web Server (Apache)         │ │ │
│  │  │  • Database (MySQL)            │ │ │
│  │  │  • SSH Server                  │ │ │
│  │  │  • Log Monitoring              │ │ │
│  │  └─────────────────────────────────┘ │ │
│  └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

## Prerequisites

- **VirtualBox** 6.0+ installed
- **Vagrant** 2.2+ installed
- **8GB RAM** available for VM
- **20GB** free disk space
- Basic command-line familiarity

## Quick Start

```bash
# Clone the repository
git clone https://github.com/giovannide/Digital-Forge.git
cd Digital-Forge/1-Cybersecurity/System-Hardening/linux-basics-lab

# Start the lab environment
vagrant up

# Connect to the lab VM
vagrant ssh

# Begin the exercises
cd /home/vagrant/lab-exercises
./start-lab.sh
```

## Lab Exercises

### Exercise 1: File Permissions and Ownership
**Objective**: Master Linux file permission system
**Duration**: 45 minutes

```bash
# Navigate to exercise directory
cd /home/vagrant/lab-exercises/01-file-permissions

# Follow the lab manual
cat LAB_MANUAL.md
```

**Key Concepts:**
- Read, write, execute permissions
- User, group, other permission sets
- Special permissions (setuid, setgid, sticky bit)
- Access Control Lists (ACLs)

### Exercise 2: User and Group Management
**Objective**: Secure user account administration
**Duration**: 60 minutes

```bash
# Navigate to exercise directory
cd /home/vagrant/lab-exercises/02-user-management

# Start the exercise
./setup-users.sh
```

**Key Concepts:**
- User account creation and management
- Password policies and aging
- Group membership and permissions
- Sudo configuration and privileges

### Exercise 3: Network Security Configuration
**Objective**: Configure basic network security
**Duration**: 90 minutes

```bash
# Navigate to exercise directory
cd /home/vagrant/lab-exercises/03-network-security

# Review current network configuration
./network-audit.sh
```

**Key Concepts:**
- Firewall configuration (iptables/ufw)
- SSH hardening and key-based authentication
- Network service security
- Port scanning and service enumeration

### Exercise 4: System Monitoring and Logging
**Objective**: Implement security monitoring
**Duration**: 75 minutes

```bash
# Navigate to exercise directory
cd /home/vagrant/lab-exercises/04-monitoring

# Configure log monitoring
./setup-monitoring.sh
```

**Key Concepts:**
- System log analysis
- Intrusion detection basics
- Performance monitoring
- Automated alerting

### Exercise 5: Security Hardening
**Objective**: Apply comprehensive security measures
**Duration**: 120 minutes

```bash
# Navigate to exercise directory
cd /home/vagrant/lab-exercises/05-hardening

# Run security assessment
./security-baseline.sh
```

**Key Concepts:**
- Security benchmarks (CIS, STIG)
- Service minimization
- Kernel security parameters
- Security updates and patch management

## Lab Manual Structure

Each exercise includes:
- **Objectives** - Clear learning goals
- **Background** - Theoretical foundation
- **Procedures** - Step-by-step instructions
- **Verification** - How to confirm success
- **Challenges** - Advanced scenarios
- **Resources** - Additional reading

## Assessment and Validation

### Automated Checks
```bash
# Run comprehensive lab validation
./validate-lab.sh

# Check specific exercise completion
./validate-exercise.sh 01-file-permissions
```

### Manual Verification
- Security configuration review
- Log analysis exercises
- Incident response scenarios
- Compliance checklist completion

## Troubleshooting

### Common Issues

1. **VM Won't Start**
   ```bash
   # Check VirtualBox installation
   vboxmanage --version
   
   # Verify Vagrant status
   vagrant status
   
   # Restart with debug output
   VAGRANT_LOG=debug vagrant up
   ```

2. **Network Connectivity Issues**
   ```bash
   # Check VM network configuration
   vagrant ssh -c "ip addr show"
   
   # Test internet connectivity
   vagrant ssh -c "ping -c 3 google.com"
   ```

3. **Permission Denied Errors**
   ```bash
   # Verify user permissions
   vagrant ssh -c "whoami && groups"
   
   # Check sudo access
   vagrant ssh -c "sudo -l"
   ```

## Security Considerations

### Lab Safety
- **Isolated Environment** - VM is isolated from host network
- **Snapshot Capability** - Easy rollback to clean state
- **No Production Data** - Only test data and configurations
- **Controlled Access** - Limited user privileges by design

### Best Practices
- Take VM snapshots before major changes
- Document all configuration changes
- Practice in lab before applying to production
- Follow principle of least privilege

## Integration with Coursework

This lab aligns with:
- **Google Cybersecurity Certificate Course 4**: Tools of the Trade - Linux and SQL
- **File Permissions in Linux** exercises
- **Linux command-line** proficiency development
- **Security fundamentals** practical application

## Advanced Scenarios

### Red Team Exercises
- Privilege escalation attempts
- Log evasion techniques
- Persistence mechanisms
- Lateral movement simulation

### Blue Team Exercises
- Incident detection and response
- Forensic analysis techniques
- Security monitoring optimization
- Compliance validation

## Resources and References

### Documentation
- [Linux Security Guide](https://www.linux.org/docs/)
- [Ubuntu Security Documentation](https://ubuntu.com/security)
- [CIS Ubuntu Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux)

### Tools and Utilities
- **Lynis** - Security auditing tool
- **Chkrootkit** - Rootkit detection
- **Fail2ban** - Intrusion prevention
- **AIDE** - File integrity monitoring

## Contributing

See [CONTRIBUTING.md](../../../../docs/CONTRIBUTING.md) for guidelines on contributing to this project.

## License

MIT License - see [LICENSE](../../../../LICENSE) for details.