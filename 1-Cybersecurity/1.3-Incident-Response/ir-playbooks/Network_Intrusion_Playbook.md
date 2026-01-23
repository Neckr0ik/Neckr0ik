# Network Intrusion Response Playbook

**Document Version**: 1.0  
**Last Updated**: January 2026  
**Owner**: Security Operations Team  
**Approved By**: Giovanni Oliveira, Security Analyst

---

## Executive Summary

### Purpose

Procedures for responding to unauthorized network access, lateral movement, and command-and-control (C2) activity.

### Scope

- **Incident Types Covered**: Lateral movement, SSH/RDP brute force, C2 beaconing.
- **Stakeholders**: Network Engineers, SOC, Infrastructure.

---

## Response Procedures

### Phase 1: Identification

1.  **Network Analysis**: Analyze netflow/packet data for unusual traffic patterns.
2.  **Identification of Source**: Locate the origin of the intrusion (internal vs external).
3.  **Map Compromise**: Identify all systems touched by the adversary.

### Phase 2: Containment

1.  **Network Segmentation**: Isolate compromised subnets or VLANs.
2.  **Firewall Blocking**: Block known C2 IPs and domains.
3.  **Session Termination**: Kill active unauthorized sessions (RDP, SSH, VPN).

### Phase 3: Eradication

1.  **Remove C2 Implants**: Delete webshells, beacons, and unauthorized scheduled tasks.
2.  **Password Rotation**: Force rotation of all service account passwords.

### Phase 4: Recovery

1.  **Verification**: Confirm no further beaconing activity for 48 hours.
2.  **Hardening**: Implement Zero Trust principles and multi-factor authentication.
3.  **Resume Operations**: Gradually restore network connectivity to isolated segments.
