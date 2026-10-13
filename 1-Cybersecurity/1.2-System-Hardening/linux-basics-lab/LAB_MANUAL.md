# Linux Security Lab Manual

## Table of Contents
1. [Lab Overview](#lab-overview)
2. [Exercise 1: File Permissions](#exercise-1-file-permissions)
3. [Exercise 2: User Management](#exercise-2-user-management)
4. [Exercise 3: Network Security](#exercise-3-network-security)
5. [Exercise 4: System Monitoring](#exercise-4-system-monitoring)
6. [Exercise 5: Security Hardening](#exercise-5-security-hardening)
7. [Assessment and Validation](#assessment-and-validation)

---

## Lab Overview

### Learning Objectives
By completing this lab, you will:
- Master Linux file permissions and access controls
- Understand user and group management security
- Configure basic network security measures
- Implement system monitoring and logging
- Apply comprehensive security hardening techniques

### Lab Environment
- **Operating System**: Ubuntu 20.04 LTS
- **Virtual Machine**: VirtualBox with Vagrant
- **Network**: Isolated private network (192.168.56.0/24)
- **Services**: Apache, MySQL, SSH, Rsyslog

### Safety Guidelines
- This is an isolated lab environment - safe for experimentation
- Take VM snapshots before major changes
- Document all commands and configurations
- Follow the principle of least privilege

---

## Exercise 1: File Permissions

### Objective
Master the Linux file permission system and understand how to secure files and directories.

### Duration
45 minutes

### Background
Linux file permissions are fundamental to system security. Every file and directory has three types of permissions (read, write, execute) for three categories of users (owner, group, others).

### Procedures

#### Step 1: Understanding Current Permissions
```bash
# Navigate to the lab directory
cd /home/vagrant/lab-exercises/01-file-permissions

# List files with detailed permissions
ls -la

# Examine a specific file's permissions
stat sensitive-data.txt
```

**Expected Output Analysis:**
- First character: file type (- for file, d for directory)
- Next 9 characters: permissions (rwxrwxrwx)
- Owner and group information
- File size and modification time

#### Step 2: Basic Permission Modification
```bash
# Create a test file
echo "This is sensitive information" > secret.txt

# View current permissions
ls -l secret.txt

# Remove read permission for group and others
chmod go-r secret.txt

# Verify the change
ls -l secret.txt

# Try to read as another user
su - labuser1 -c "cat /home/vagrant/lab-exercises/01-file-permissions/secret.txt"
```

#### Step 3: Numeric Permission Mode
```bash
# Set permissions using numeric mode
chmod 750 secret.txt

# Verify the permissions
ls -l secret.txt

# What do these numbers mean?
# 7 (owner): 4+2+1 = read+write+execute
# 5 (group): 4+0+1 = read+execute
# 0 (others): no permissions
```

#### Step 4: Directory Permissions
```bash
# Create a directory structure
mkdir -p secure-folder/confidential

# Set directory permissions
chmod 755 secure-folder
chmod 700 secure-folder/confidential

# Test directory access
ls -ld secure-folder secure-folder/confidential

# Try accessing as different user
su - labuser1 -c "ls /home/vagrant/lab-exercises/01-file-permissions/secure-folder/"
su - labuser1 -c "ls /home/vagrant/lab-exercises/01-file-permissions/secure-folder/confidential/"
```

#### Step 5: Special Permissions
```bash
# Create a shared directory with sticky bit
mkdir shared-temp
chmod 1777 shared-temp

# Verify sticky bit is set
ls -ld shared-temp

# Test sticky bit behavior
echo "User1 file" > shared-temp/user1-file.txt
chown labuser1:labuser1 shared-temp/user1-file.txt

# Try to delete as different user
su - labuser2 -c "rm /home/vagrant/lab-exercises/01-file-permissions/shared-temp/user1-file.txt"
```

### Verification Tasks
1. Create a file that only the owner can read and write
2. Create a directory that group members can access but not modify
3. Set up a shared directory where users can create files but not delete others' files
4. Demonstrate the difference between read and execute permissions on directories

### Challenge Scenarios
1. **Scenario A**: Configure a log directory where applications can write but not read each other's logs
2. **Scenario B**: Set up a backup directory structure with appropriate permissions for automated backups
3. **Scenario C**: Create a secure script that can be executed but not read by regular users

---

## Exercise 2: User Management

### Objective
Implement secure user account administration and understand privilege management.

### Duration
60 minutes

### Background
Proper user management is critical for system security. This includes creating accounts with appropriate privileges, implementing password policies, and managing group memberships.

### Procedures

#### Step 1: User Account Analysis
```bash
# Examine current users
cat /etc/passwd | grep -E "(vagrant|labuser)"

# Check user groups
groups vagrant
groups labuser1

# View password policies
cat /etc/login.defs | grep -E "(PASS_|UID_|GID_)"
```

#### Step 2: Creating Secure User Accounts
```bash
# Create a new user with specific settings
sudo useradd -m -s /bin/bash -c "Security Analyst" secanalyst

# Set a strong password
sudo passwd secanalyst

# Create a system account for a service
sudo useradd -r -s /bin/false -c "Web Service Account" webservice

# Verify account creation
tail -3 /etc/passwd
```

#### Step 3: Group Management
```bash
# Create security-related groups
sudo groupadd security-team
sudo groupadd audit-team
sudo groupadd incident-response

# Add users to groups
sudo usermod -a -G security-team secanalyst
sudo usermod -a -G audit-team labuser2

# Verify group memberships
groups secanalyst
getent group security-team
```

#### Step 4: Sudo Configuration
```bash
# View current sudo configuration
sudo cat /etc/sudoers

# Create custom sudo rules
sudo visudo -f /etc/sudoers.d/security-team

# Add the following content:
# %security-team ALL=(ALL) /usr/bin/nmap, /usr/bin/tcpdump, /bin/systemctl status *
# secanalyst ALL=(ALL) NOPASSWD: /usr/bin/lynis

# Test sudo access
sudo -u secanalyst sudo -l
```

#### Step 5: Password Security
```bash
# Check password aging information
sudo chage -l vagrant

# Set password aging policy for new user
sudo chage -M 90 -m 7 -W 14 secanalyst

# Force password change on next login
sudo chage -d 0 labuser1

# View updated password information
sudo chage -l secanalyst
```

### Verification Tasks
1. Create a user account that can only run specific security tools
2. Set up a group that can read log files but not modify them
3. Configure password aging for all lab users
4. Demonstrate privilege escalation using sudo

### Challenge Scenarios
1. **Scenario A**: Create a "read-only admin" account that can view system information but not make changes
2. **Scenario B**: Set up a service account with minimal privileges for running a web application
3. **Scenario C**: Implement a user account that automatically expires after 30 days

---

## Exercise 3: Network Security

### Objective
Configure basic network security measures including firewall rules and SSH hardening.

### Duration
90 minutes

### Background
Network security is the first line of defense against external threats. This exercise covers firewall configuration, SSH security, and network service management.

### Procedures

#### Step 1: Network Assessment
```bash
# Check current network configuration
ip addr show
ip route show

# Identify listening services
sudo netstat -tlnp
sudo ss -tlnp

# Scan for open ports
nmap localhost
nmap 192.168.56.10
```

#### Step 2: Firewall Configuration (UFW)
```bash
# Check current firewall status
sudo ufw status verbose

# Reset firewall to default state
sudo ufw --force reset

# Set default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow specific services
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow from specific IP range
sudo ufw allow from 192.168.56.0/24

# Enable firewall
sudo ufw enable

# Verify configuration
sudo ufw status numbered
```

#### Step 3: SSH Hardening
```bash
# Backup original SSH configuration
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Edit SSH configuration
sudo nano /etc/ssh/sshd_config

# Key security settings to modify:
# Port 2222
# PermitRootLogin no
# PasswordAuthentication no
# PubkeyAuthentication yes
# MaxAuthTries 3
# ClientAliveInterval 300
# ClientAliveCountMax 2

# Generate SSH key pair for secure authentication
ssh-keygen -t rsa -b 4096 -C "lab-security-key"

# Copy public key to authorized_keys
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Test SSH configuration
sudo sshd -t

# Restart SSH service
sudo systemctl restart ssh
```

#### Step 4: Service Security
```bash
# List all running services
sudo systemctl list-units --type=service --state=running

# Disable unnecessary services
sudo systemctl disable bluetooth
sudo systemctl stop bluetooth

# Secure Apache configuration
sudo nano /etc/apache2/conf-available/security.conf

# Key security settings:
# ServerTokens Prod
# ServerSignature Off
# Header always set X-Content-Type-Options nosniff
# Header always set X-Frame-Options DENY

# Enable security configuration
sudo a2enconf security
sudo systemctl restart apache2
```

#### Step 5: Network Monitoring
```bash
# Monitor network connections
sudo netstat -tuln
sudo ss -tuln

# Monitor network traffic
sudo tcpdump -i any -n -c 10

# Check for suspicious connections
sudo netstat -an | grep ESTABLISHED
```

### Verification Tasks
1. Configure firewall to allow only necessary services
2. Implement SSH key-based authentication
3. Disable unnecessary network services
4. Monitor network traffic for suspicious activity

### Challenge Scenarios
1. **Scenario A**: Configure port knocking for SSH access
2. **Scenario B**: Set up a DMZ-like network configuration
3. **Scenario C**: Implement network intrusion detection

---

## Exercise 4: System Monitoring

### Objective
Implement comprehensive system monitoring and logging for security purposes.

### Duration
75 minutes

### Background
Effective monitoring and logging are essential for detecting security incidents and maintaining system health. This exercise covers log analysis, monitoring tools, and alerting mechanisms.

### Procedures

#### Step 1: Log Analysis Fundamentals
```bash
# Examine system logs
sudo tail -f /var/log/syslog
sudo tail -f /var/log/auth.log
sudo tail -f /var/log/apache2/access.log

# Search for specific events
sudo grep "Failed password" /var/log/auth.log
sudo grep "sudo" /var/log/auth.log
sudo grep "ERROR" /var/log/syslog

# Analyze log patterns
sudo awk '/Failed password/ {print $1, $2, $3, $11}' /var/log/auth.log | sort | uniq -c
```

#### Step 2: System Performance Monitoring
```bash
# Monitor system resources
htop
iotop
nethogs

# Check system load and uptime
uptime
w

# Monitor disk usage
df -h
du -sh /var/log/*

# Check memory usage
free -h
cat /proc/meminfo
```

#### Step 3: Security Monitoring Tools
```bash
# Run Lynis security audit
sudo lynis audit system

# Check for rootkits
sudo chkrootkit

# Monitor file integrity with AIDE
sudo aide --check

# Check for failed login attempts
sudo lastb

# Monitor successful logins
last
```

#### Step 4: Custom Monitoring Scripts
```bash
# Create a security monitoring script
cat > /home/vagrant/security-monitor.sh << 'EOF'
#!/bin/bash
# Security monitoring script

LOG_FILE="/var/log/lab/security-monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$DATE] Starting security check" >> $LOG_FILE

# Check for failed login attempts
FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log | wc -l)
if [ $FAILED_LOGINS -gt 10 ]; then
    echo "[$DATE] WARNING: $FAILED_LOGINS failed login attempts detected" >> $LOG_FILE
fi

# Check disk usage
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 80 ]; then
    echo "[$DATE] WARNING: Disk usage is $DISK_USAGE%" >> $LOG_FILE
fi

# Check for suspicious processes
ps aux | grep -E "(nc|netcat|nmap)" | grep -v grep >> $LOG_FILE

echo "[$DATE] Security check completed" >> $LOG_FILE
EOF

chmod +x /home/vagrant/security-monitor.sh

# Run the monitoring script
./security-monitor.sh
cat /var/log/lab/security-monitor.log
```

#### Step 5: Log Rotation and Retention
```bash
# Configure log rotation
sudo nano /etc/logrotate.d/lab-security

# Add configuration:
# /var/log/lab/*.log {
#     daily
#     missingok
#     rotate 30
#     compress
#     delaycompress
#     notifempty
#     create 644 root root
# }

# Test log rotation
sudo logrotate -d /etc/logrotate.d/lab-security
```

### Verification Tasks
1. Identify and analyze security-related log entries
2. Set up automated monitoring for system resources
3. Configure alerting for suspicious activities
4. Implement log retention policies

### Challenge Scenarios
1. **Scenario A**: Create a dashboard for real-time security monitoring
2. **Scenario B**: Implement automated incident response based on log analysis
3. **Scenario C**: Set up centralized logging for multiple systems

---

## Exercise 5: Security Hardening

### Objective
Apply comprehensive security hardening measures based on industry standards.

### Duration
120 minutes

### Background
Security hardening involves implementing multiple layers of security controls to reduce the attack surface and improve overall system security posture.

### Procedures

#### Step 1: Security Baseline Assessment
```bash
# Run comprehensive security audit
sudo lynis audit system --profile /etc/lynis/default.prf

# Generate security report
sudo lynis show report

# Check CIS benchmark compliance
# (Note: This would typically use a CIS-CAT tool in production)
```

#### Step 2: Kernel Security Parameters
```bash
# View current kernel parameters
sysctl -a | grep -E "(net.ipv4|kernel)"

# Configure security-related kernel parameters
sudo nano /etc/sysctl.d/99-security.conf

# Add security settings:
# # Network security
# net.ipv4.ip_forward = 0
# net.ipv4.conf.all.send_redirects = 0
# net.ipv4.conf.default.send_redirects = 0
# net.ipv4.conf.all.accept_redirects = 0
# net.ipv4.conf.default.accept_redirects = 0
# net.ipv4.conf.all.accept_source_route = 0
# net.ipv4.conf.default.accept_source_route = 0
# net.ipv4.conf.all.log_martians = 1
# net.ipv4.conf.default.log_martians = 1
# net.ipv4.icmp_echo_ignore_broadcasts = 1
# net.ipv4.icmp_ignore_bogus_error_responses = 1
# net.ipv4.tcp_syncookies = 1
# 
# # Kernel security
# kernel.dmesg_restrict = 1
# kernel.kptr_restrict = 2
# kernel.yama.ptrace_scope = 1

# Apply the settings
sudo sysctl -p /etc/sysctl.d/99-security.conf
```

#### Step 3: Service Hardening
```bash
# Audit running services
sudo systemctl list-units --type=service --state=running

# Disable unnecessary services
sudo systemctl disable avahi-daemon
sudo systemctl stop avahi-daemon

# Secure shared memory
echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" | sudo tee -a /etc/fstab

# Configure automatic updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

#### Step 4: Access Control Hardening
```bash
# Configure login restrictions
sudo nano /etc/security/limits.conf

# Add limits:
# * hard maxlogins 3
# * hard core 0

# Configure PAM for account lockout
sudo nano /etc/pam.d/common-auth

# Add after the pam_unix.so line:
# auth required pam_tally2.so deny=3 unlock_time=600 onerr=fail

# Set file creation mask
echo "umask 027" | sudo tee -a /etc/profile
```

#### Step 5: Audit and Compliance
```bash
# Install and configure auditd
sudo apt install auditd audispd-plugins

# Configure audit rules
sudo nano /etc/audit/rules.d/audit.rules

# Add audit rules:
# # Monitor authentication events
# -w /etc/passwd -p wa -k identity
# -w /etc/group -p wa -k identity
# -w /etc/shadow -p wa -k identity
# -w /etc/sudoers -p wa -k identity
# 
# # Monitor system calls
# -a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
# -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
# 
# # Monitor network configuration
# -a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
# -a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale

# Restart auditd
sudo systemctl restart auditd

# Test audit logging
sudo ausearch -k identity
```

### Verification Tasks
1. Verify all security configurations are applied correctly
2. Run security assessment tools to validate hardening
3. Test system functionality after hardening
4. Document all security changes made

### Challenge Scenarios
1. **Scenario A**: Implement a complete CIS benchmark compliance
2. **Scenario B**: Create a custom security hardening script
3. **Scenario C**: Set up continuous compliance monitoring

---

## Assessment and Validation

### Automated Validation Script
```bash
#!/bin/bash
# Lab validation script

echo "=== Linux Security Lab Validation ==="

# Check Exercise 1: File Permissions
echo "Checking file permissions..."
if [ -f "/home/vagrant/lab-exercises/01-file-permissions/secret.txt" ]; then
    PERMS=$(stat -c "%a" /home/vagrant/lab-exercises/01-file-permissions/secret.txt)
    if [ "$PERMS" = "750" ]; then
        echo "✅ File permissions correctly set"
    else
        echo "❌ File permissions incorrect: $PERMS"
    fi
fi

# Check Exercise 2: User Management
echo "Checking user management..."
if id secanalyst &>/dev/null; then
    echo "✅ Security analyst user created"
else
    echo "❌ Security analyst user not found"
fi

# Check Exercise 3: Network Security
echo "Checking firewall configuration..."
UFW_STATUS=$(sudo ufw status | grep "Status: active")
if [ -n "$UFW_STATUS" ]; then
    echo "✅ Firewall is active"
else
    echo "❌ Firewall is not active"
fi

# Check Exercise 4: Monitoring
echo "Checking monitoring setup..."
if [ -f "/home/vagrant/security-monitor.sh" ]; then
    echo "✅ Security monitoring script exists"
else
    echo "❌ Security monitoring script not found"
fi

# Check Exercise 5: Hardening
echo "Checking security hardening..."
if [ -f "/etc/sysctl.d/99-security.conf" ]; then
    echo "✅ Kernel security parameters configured"
else
    echo "❌ Kernel security parameters not configured"
fi

echo "=== Validation Complete ==="
```

### Manual Verification Checklist

#### Exercise 1: File Permissions
- [ ] Can create files with specific permissions
- [ ] Understands numeric and symbolic permission modes
- [ ] Can configure directory permissions correctly
- [ ] Knows how to use special permissions (sticky bit, setuid, setgid)

#### Exercise 2: User Management
- [ ] Can create users with appropriate settings
- [ ] Understands group management and membership
- [ ] Can configure sudo access properly
- [ ] Knows how to implement password policies

#### Exercise 3: Network Security
- [ ] Can configure firewall rules effectively
- [ ] Understands SSH security hardening
- [ ] Can identify and secure network services
- [ ] Knows how to monitor network activity

#### Exercise 4: System Monitoring
- [ ] Can analyze system and security logs
- [ ] Understands how to use monitoring tools
- [ ] Can create custom monitoring scripts
- [ ] Knows how to configure log retention

#### Exercise 5: Security Hardening
- [ ] Can apply kernel security parameters
- [ ] Understands service hardening techniques
- [ ] Can configure access controls
- [ ] Knows how to implement audit logging

### Performance Metrics
- **Completion Time**: Track time spent on each exercise
- **Error Rate**: Number of mistakes made during exercises
- **Security Score**: Based on Lynis audit results
- **Compliance Level**: Percentage of security controls implemented

### Additional Resources
- [Linux Security Guide](https://www.linux.org/docs/)
- [Ubuntu Security Documentation](https://ubuntu.com/security)
- [CIS Ubuntu Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

**Lab Manual Version**: 1.0  
**Last Updated**: December 2024  
**Author**: Giovanni Oliveira  
**Project**: Digital-Forge