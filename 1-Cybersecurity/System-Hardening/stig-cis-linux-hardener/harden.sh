#!/bin/bash
#
# STIG/CIS Linux Hardening Script
# Author: Giovanni Oliveira
# Description: Automated security hardening based on DISA STIG and CIS benchmarks
# Version: 1.0
#

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config/hardening.conf"
LOG_FILE="/var/log/hardening.log"
BACKUP_DIR="/var/backups/hardening/$(date +%Y%m%d_%H%M%S)"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
DRY_RUN=false
FORCE=false
CATEGORY=""
VERBOSE=false

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
    
    case "$level" in
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message" >&2
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} $message"
            ;;
    esac
}

# Error handling
error_exit() {
    log "ERROR" "$1"
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root. Use sudo."
    fi
}

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        log "INFO" "Configuration loaded from $CONFIG_FILE"
    else
        log "WARN" "Configuration file not found, using defaults"
        # Set default values
        ENABLE_NETWORK_HARDENING=true
        ENABLE_SSH_HARDENING=true
        ENABLE_AUDIT_LOGGING=true
        ENABLE_FILE_PERMISSIONS=true
        APPLY_STIG_CONTROLS=true
        APPLY_CIS_CONTROLS=true
        CREATE_BACKUPS=true
        BACKUP_LOCATION="/var/backups/hardening"
    fi
}

# Create backup
create_backup() {
    if [[ "$CREATE_BACKUPS" == "true" ]]; then
        log "INFO" "Creating system backup..."
        mkdir -p "$BACKUP_DIR"
        
        # Backup critical configuration files
        local files_to_backup=(
            "/etc/ssh/sshd_config"
            "/etc/sysctl.conf"
            "/etc/sysctl.d/"
            "/etc/security/"
            "/etc/pam.d/"
            "/etc/audit/"
            "/etc/sudoers"
            "/etc/passwd"
            "/etc/shadow"
            "/etc/group"
            "/etc/gshadow"
            "/etc/login.defs"
            "/etc/fstab"
        )
        
        for file in "${files_to_backup[@]}"; do
            if [[ -e "$file" ]]; then
                cp -r "$file" "$BACKUP_DIR/" 2>/dev/null || true
            fi
        done
        
        # Create system state snapshot
        {
            echo "=== System Information ==="
            uname -a
            echo ""
            echo "=== Installed Packages ==="
            dpkg -l 2>/dev/null || rpm -qa 2>/dev/null || true
            echo ""
            echo "=== Running Services ==="
            systemctl list-units --type=service --state=running
            echo ""
            echo "=== Network Configuration ==="
            ip addr show
            echo ""
            echo "=== Firewall Status ==="
            ufw status verbose 2>/dev/null || iptables -L 2>/dev/null || true
        } > "$BACKUP_DIR/system_state.txt"
        
        log "SUCCESS" "Backup created at $BACKUP_DIR"
    fi
}

# Network hardening
harden_network() {
    if [[ "$ENABLE_NETWORK_HARDENING" != "true" ]]; then
        log "INFO" "Network hardening disabled, skipping..."
        return
    fi
    
    log "INFO" "Applying network security hardening..."
    
    # Disable unused network protocols
    local protocols=("dccp" "sctp" "rds" "tipc")
    for protocol in "${protocols[@]}"; do
        if ! $DRY_RUN; then
            echo "install $protocol /bin/true" >> /etc/modprobe.d/blacklist-rare-network.conf
        fi
        log "INFO" "Disabled protocol: $protocol"
    done
    
    # Configure kernel network parameters
    local sysctl_config="/etc/sysctl.d/99-stig-network.conf"
    if ! $DRY_RUN; then
        cat > "$sysctl_config" << 'EOF'
# Network security parameters - STIG/CIS compliance
# Disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable accept redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Enable logging of suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# Disable IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF
        
        # Apply the settings
        sysctl -p "$sysctl_config"
    fi
    
    log "SUCCESS" "Network hardening completed"
}

# SSH hardening
harden_ssh() {
    if [[ "$ENABLE_SSH_HARDENING" != "true" ]]; then
        log "INFO" "SSH hardening disabled, skipping..."
        return
    fi
    
    log "INFO" "Applying SSH security hardening..."
    
    local ssh_config="/etc/ssh/sshd_config"
    
    if ! $DRY_RUN; then
        # Create hardened SSH configuration
        cp "$ssh_config" "${ssh_config}.backup"
        
        # Apply SSH hardening settings
        sed -i 's/#Protocol 2/Protocol 2/' "$ssh_config"
        sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' "$ssh_config"
        sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' "$ssh_config"
        sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' "$ssh_config"
        sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' "$ssh_config"
        sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' "$ssh_config"
        sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/' "$ssh_config"
        sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 2/' "$ssh_config"
        sed -i 's/#LoginGraceTime 2m/LoginGraceTime 60/' "$ssh_config"
        sed -i 's/#MaxStartups 10:30:100/MaxStartups 10:30:60/' "$ssh_config"
        
        # Add additional security settings
        cat >> "$ssh_config" << 'EOF'

# Additional security settings
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
PermitUserEnvironment no
Compression no
UseDNS no
PrintMotd no
PrintLastLog yes
TCPKeepAlive no
UsePrivilegeSeparation sandbox
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
RhostsRSAAuthentication no
RSAAuthentication yes
KerberosAuthentication no
GSSAPIAuthentication no
ChallengeResponseAuthentication no
UsePAM yes

# Allowed users and groups (customize as needed)
# AllowUsers user1 user2
# AllowGroups ssh-users

# Ciphers and algorithms
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256,hmac-sha2-512
KexAlgorithms diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256
EOF
        
        # Test SSH configuration
        if sshd -t; then
            systemctl restart ssh
            log "SUCCESS" "SSH configuration applied and service restarted"
        else
            log "ERROR" "SSH configuration test failed, restoring backup"
            cp "${ssh_config}.backup" "$ssh_config"
            return 1
        fi
    fi
    
    log "SUCCESS" "SSH hardening completed"
}

# Authentication and access control hardening
harden_authentication() {
    log "INFO" "Applying authentication and access control hardening..."
    
    # Configure password quality
    if ! $DRY_RUN; then
        cat > /etc/security/pwquality.conf << 'EOF'
# Password quality requirements - STIG compliance
minlen = 15
minclass = 4
maxrepeat = 2
maxclassrepeat = 4
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 8
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
EOF
    fi
    
    # Configure account lockout
    local pam_auth="/etc/pam.d/common-auth"
    if [[ -f "$pam_auth" ]] && ! $DRY_RUN; then
        # Add account lockout if not already present
        if ! grep -q "pam_tally2" "$pam_auth"; then
            sed -i '/pam_unix.so/a auth required pam_tally2.so deny=3 unlock_time=604800 onerr=fail' "$pam_auth"
        fi
    fi
    
    # Configure login definitions
    if ! $DRY_RUN; then
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
        sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
    fi
    
    # Configure sudo settings
    if ! $DRY_RUN; then
        cat > /etc/sudoers.d/security-hardening << 'EOF'
# Security hardening for sudo
Defaults timestamp_timeout=5
Defaults !visiblepw
Defaults always_set_home
Defaults match_group_by_gid
Defaults always_query_group_plugin
Defaults env_reset
Defaults env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS"
Defaults env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE"
Defaults env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES"
Defaults env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE"
Defaults env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY"
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
EOF
    fi
    
    log "SUCCESS" "Authentication hardening completed"
}

# File system hardening
harden_filesystem() {
    log "INFO" "Applying file system security hardening..."
    
    # Set secure file permissions
    local files_permissions=(
        "/etc/passwd:644"
        "/etc/shadow:640"
        "/etc/group:644"
        "/etc/gshadow:640"
        "/etc/sudoers:440"
        "/etc/ssh/sshd_config:600"
        "/boot/grub/grub.cfg:600"
    )
    
    for file_perm in "${files_permissions[@]}"; do
        local file="${file_perm%:*}"
        local perm="${file_perm#*:}"
        
        if [[ -f "$file" ]] && ! $DRY_RUN; then
            chmod "$perm" "$file"
            log "INFO" "Set permissions $perm on $file"
        fi
    done
    
    # Configure secure mount options in fstab
    if ! $DRY_RUN; then
        # Add nodev, nosuid, noexec to /tmp if not already present
        if ! grep -q "/tmp.*nodev" /etc/fstab; then
            echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
        fi
        
        # Add nodev, nosuid, noexec to /var/tmp if not already present
        if ! grep -q "/var/tmp.*nodev" /etc/fstab; then
            echo "tmpfs /var/tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
        fi
    fi
    
    # Set umask for all users
    if ! $DRY_RUN; then
        echo "umask 027" >> /etc/profile
        echo "umask 027" >> /etc/bash.bashrc
    fi
    
    log "SUCCESS" "File system hardening completed"
}

# Audit logging configuration
configure_audit_logging() {
    if [[ "$ENABLE_AUDIT_LOGGING" != "true" ]]; then
        log "INFO" "Audit logging disabled, skipping..."
        return
    fi
    
    log "INFO" "Configuring comprehensive audit logging..."
    
    # Install auditd if not present
    if ! command -v auditd &> /dev/null; then
        if ! $DRY_RUN; then
            apt-get update && apt-get install -y auditd audispd-plugins
        fi
    fi
    
    # Configure audit rules
    if ! $DRY_RUN; then
        cat > /etc/audit/rules.d/stig.rules << 'EOF'
# Delete all existing rules
-D

# Buffer size
-b 8192

# Failure mode (0=silent, 1=printk, 2=panic)
-f 1

# Monitor authentication events
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/sudoers.d/ -p wa -k identity

# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change

# Monitor network configuration
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale

# Monitor file access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access

# Monitor privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Monitor kernel module loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Make rules immutable
-e 2
EOF
        
        # Restart auditd
        systemctl enable auditd
        systemctl restart auditd
    fi
    
    log "SUCCESS" "Audit logging configuration completed"
}

# Kernel hardening
harden_kernel() {
    log "INFO" "Applying kernel security hardening..."
    
    if ! $DRY_RUN; then
        cat > /etc/sysctl.d/99-stig-kernel.conf << 'EOF'
# Kernel security parameters - STIG compliance

# Restrict access to kernel logs
kernel.dmesg_restrict = 1

# Restrict access to kernel pointers
kernel.kptr_restrict = 2

# Restrict ptrace scope
kernel.yama.ptrace_scope = 1

# Disable magic SysRq key
kernel.sysrq = 0

# Control core dumps
fs.suid_dumpable = 0

# Address space layout randomization
kernel.randomize_va_space = 2

# Restrict access to kernel address
kernel.kexec_load_disabled = 1

# Disable user namespaces
user.max_user_namespaces = 0
EOF
        
        # Apply kernel parameters
        sysctl -p /etc/sysctl.d/99-stig-kernel.conf
    fi
    
    log "SUCCESS" "Kernel hardening completed"
}

# Service hardening
harden_services() {
    log "INFO" "Applying service security hardening..."
    
    # List of services to disable (customize based on requirements)
    local services_to_disable=(
        "avahi-daemon"
        "cups"
        "bluetooth"
        "rpcbind"
        "nfs-server"
        "ypbind"
        "tftp"
        "xinetd"
    )
    
    for service in "${services_to_disable[@]}"; do
        if systemctl is-enabled "$service" &>/dev/null; then
            if ! $DRY_RUN; then
                systemctl disable "$service"
                systemctl stop "$service"
            fi
            log "INFO" "Disabled service: $service"
        fi
    done
    
    # Configure automatic updates
    if ! $DRY_RUN; then
        apt-get install -y unattended-upgrades
        dpkg-reconfigure -plow unattended-upgrades
    fi
    
    log "SUCCESS" "Service hardening completed"
}

# Main hardening function
apply_hardening() {
    log "INFO" "Starting system hardening process..."
    
    case "$CATEGORY" in
        "network")
            harden_network
            ;;
        "ssh")
            harden_ssh
            ;;
        "authentication")
            harden_authentication
            ;;
        "filesystem")
            harden_filesystem
            ;;
        "audit")
            configure_audit_logging
            ;;
        "kernel")
            harden_kernel
            ;;
        "services")
            harden_services
            ;;
        "")
            # Apply all hardening categories
            harden_network
            harden_ssh
            harden_authentication
            harden_filesystem
            configure_audit_logging
            harden_kernel
            harden_services
            ;;
        *)
            error_exit "Unknown category: $CATEGORY"
            ;;
    esac
    
    log "SUCCESS" "System hardening completed successfully"
}

# Generate summary report
generate_summary() {
    log "INFO" "Generating hardening summary..."
    
    local summary_file="/var/log/hardening-summary-$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "=== SYSTEM HARDENING SUMMARY ==="
        echo "Date: $(date)"
        echo "Hostname: $(hostname)"
        echo "OS: $(lsb_release -d 2>/dev/null | cut -f2 || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
        echo "Kernel: $(uname -r)"
        echo ""
        echo "=== HARDENING APPLIED ==="
        echo "Network Hardening: $ENABLE_NETWORK_HARDENING"
        echo "SSH Hardening: $ENABLE_SSH_HARDENING"
        echo "Authentication Hardening: $ENABLE_AUTHENTICATION_HARDENING"
        echo "File System Hardening: $ENABLE_FILE_PERMISSIONS"
        echo "Audit Logging: $ENABLE_AUDIT_LOGGING"
        echo ""
        echo "=== BACKUP LOCATION ==="
        echo "$BACKUP_DIR"
        echo ""
        echo "=== NEXT STEPS ==="
        echo "1. Review hardening log: $LOG_FILE"
        echo "2. Test system functionality"
        echo "3. Run compliance assessment: ./assess-compliance.sh"
        echo "4. Configure monitoring and alerting"
        echo ""
    } | tee "$summary_file"
    
    log "SUCCESS" "Summary report generated: $summary_file"
}

# Usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

STIG/CIS Linux Hardening Script

OPTIONS:
    -c, --category CATEGORY    Apply specific category hardening
                              (network, ssh, authentication, filesystem, audit, kernel, services)
    -d, --dry-run             Show what would be changed without applying
    -f, --force               Skip confirmation prompts
    -v, --verbose             Enable verbose output
    -h, --help                Show this help message

EXAMPLES:
    $0                        Apply all hardening categories
    $0 --category network     Apply only network hardening
    $0 --dry-run              Show changes without applying them
    $0 --force --category ssh Apply SSH hardening without prompts

EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--category)
                CATEGORY="$2"
                shift 2
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -f|--force)
                FORCE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error_exit "Unknown option: $1"
                ;;
        esac
    done
}

# Confirmation prompt
confirm_hardening() {
    if [[ "$FORCE" == "true" ]]; then
        return 0
    fi
    
    echo -e "${YELLOW}WARNING: This script will apply security hardening to your system.${NC}"
    echo -e "${YELLOW}This may affect system functionality and network connectivity.${NC}"
    echo ""
    echo "Hardening scope: ${CATEGORY:-"All categories"}"
    echo "Dry run mode: $DRY_RUN"
    echo "Backup will be created: $CREATE_BACKUPS"
    echo ""
    read -p "Do you want to continue? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "INFO" "Hardening cancelled by user"
        exit 0
    fi
}

# Main function
main() {
    # Initialize logging
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    
    log "INFO" "Starting STIG/CIS Linux Hardening Script v1.0"
    log "INFO" "Author: Giovanni Oliveira"
    
    # Parse arguments
    parse_arguments "$@"
    
    # Check prerequisites
    check_root
    load_config
    
    # Show what will be done
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN MODE - No changes will be applied"
    fi
    
    # Confirm before proceeding
    confirm_hardening
    
    # Create backup
    create_backup
    
    # Apply hardening
    apply_hardening
    
    # Generate summary
    generate_summary
    
    log "SUCCESS" "Hardening process completed successfully!"
    
    if [[ "$DRY_RUN" == "false" ]]; then
        echo ""
        echo -e "${GREEN}System hardening completed!${NC}"
        echo -e "${BLUE}Next steps:${NC}"
        echo "1. Reboot the system to ensure all changes take effect"
        echo "2. Test system functionality and network connectivity"
        echo "3. Run compliance assessment: ./assess-compliance.sh"
        echo "4. Review logs: $LOG_FILE"
        echo ""
        echo -e "${YELLOW}If you encounter issues, you can rollback using:${NC}"
        echo "./rollback.sh --restore $BACKUP_DIR"
    fi
}

# Run main function with all arguments
main "$@"