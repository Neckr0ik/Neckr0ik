#!/usr/bin/env python3
"""
Network Packet Sniffer using Scapy
Author: Giovanni Oliveira
Description: Real-time network packet analyzer for security monitoring
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from typing import Dict, List, Optional

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
    from scapy.layers.inet import Ether
except ImportError:
    print("Error: Scapy not installed. Run: pip install scapy")
    sys.exit(1)

class PacketSniffer:
    """Network packet sniffer with threat detection capabilities."""
    
    def __init__(self, interface: str = "eth0", config_file: str = "config.json"):
        self.interface = interface
        self.packet_count = 0
        self.suspicious_ips = set()
        self.port_scan_attempts = {}
        self.config = self.load_config(config_file)
        self.setup_logging()
    
    def load_config(self, config_file: str) -> Dict:
        """Load configuration from JSON file."""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return self.default_config()
    
    def default_config(self) -> Dict:
        """Return default configuration."""
        return {
            "suspicious_ports": [22, 23, 135, 139, 445, 1433, 3389],
            "max_connections_per_ip": 50,
            "scan_threshold": 10,
            "log_level": "INFO",
            "output_file": "packet_analysis.log"
        }
    
    def setup_logging(self):
        """Configure logging for packet analysis."""
        logging.basicConfig(
            level=getattr(logging, self.config["log_level"]),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config["output_file"]),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def analyze_packet(self, packet):
        """Analyze individual packet for security threats."""
        self.packet_count += 1
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Log basic packet information
            self.logger.debug(f"Packet {self.packet_count}: {src_ip} -> {dst_ip}")
            
            # Detect potential port scanning
            if TCP in packet:
                self.detect_port_scan(src_ip, packet[TCP].dport)
            
            # Check for suspicious ports
            if self.is_suspicious_port(packet):
                self.logger.warning(f"Suspicious port activity: {src_ip} -> {dst_ip}")
                self.suspicious_ips.add(src_ip)
            
            # Analyze ARP packets for potential ARP spoofing
            if ARP in packet:
                self.detect_arp_spoofing(packet)
    
    def detect_port_scan(self, src_ip: str, dst_port: int):
        """Detect potential port scanning attempts."""
        if src_ip not in self.port_scan_attempts:
            self.port_scan_attempts[src_ip] = set()
        
        self.port_scan_attempts[src_ip].add(dst_port)
        
        if len(self.port_scan_attempts[src_ip]) > self.config["scan_threshold"]:
            self.logger.warning(f"Potential port scan detected from {src_ip}")
            self.suspicious_ips.add(src_ip)
    
    def is_suspicious_port(self, packet) -> bool:
        """Check if packet involves suspicious ports."""
        if TCP in packet:
            return packet[TCP].dport in self.config["suspicious_ports"]
        elif UDP in packet:
            return packet[UDP].dport in self.config["suspicious_ports"]
        return False
    
    def detect_arp_spoofing(self, packet):
        """Detect potential ARP spoofing attacks."""
        if packet[ARP].op == 2:  # ARP reply
            self.logger.info(f"ARP Reply: {packet[ARP].psrc} is at {packet[ARP].hwsrc}")
    
    def print_packet_summary(self, packet):
        """Print human-readable packet summary."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            
            if TCP in packet:
                print(f"[{timestamp}] TCP: {src_ip}:{packet[TCP].sport} -> {dst_ip}:{packet[TCP].dport}")
            elif UDP in packet:
                print(f"[{timestamp}] UDP: {src_ip}:{packet[UDP].sport} -> {dst_ip}:{packet[UDP].dport}")
            elif ICMP in packet:
                print(f"[{timestamp}] ICMP: {src_ip} -> {dst_ip}")
            else:
                print(f"[{timestamp}] IP: {src_ip} -> {dst_ip} (Protocol: {protocol})")
    
    def start_sniffing(self, count: int = 0, verbose: bool = False):
        """Start packet capture and analysis."""
        self.logger.info(f"Starting packet capture on interface {self.interface}")
        
        try:
            if verbose:
                sniff(
                    iface=self.interface,
                    prn=lambda x: (self.analyze_packet(x), self.print_packet_summary(x)),
                    count=count,
                    store=False
                )
            else:
                sniff(
                    iface=self.interface,
                    prn=self.analyze_packet,
                    count=count,
                    store=False
                )
        except KeyboardInterrupt:
            self.logger.info("Packet capture interrupted by user")
        except Exception as e:
            self.logger.error(f"Error during packet capture: {e}")
        finally:
            self.generate_report()
    
    def generate_report(self):
        """Generate security analysis report."""
        self.logger.info("=== PACKET ANALYSIS REPORT ===")
        self.logger.info(f"Total packets analyzed: {self.packet_count}")
        self.logger.info(f"Suspicious IPs detected: {len(self.suspicious_ips)}")
        
        if self.suspicious_ips:
            self.logger.warning("Suspicious IP addresses:")
            for ip in self.suspicious_ips:
                self.logger.warning(f"  - {ip}")
        
        if self.port_scan_attempts:
            self.logger.info("Port scan attempts detected:")
            for ip, ports in self.port_scan_attempts.items():
                if len(ports) > self.config["scan_threshold"]:
                    self.logger.warning(f"  - {ip}: {len(ports)} ports scanned")

def main():
    """Main function with command-line interface."""
    parser = argparse.ArgumentParser(description="Network Packet Sniffer with Security Analysis")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface to monitor")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--config", default="config.json", help="Configuration file path")
    
    args = parser.parse_args()
    
    # Check if running with sufficient privileges
    if sys.platform.startswith('linux') and os.geteuid() != 0:
        print("Error: This script requires root privileges for packet capture.")
        print("Please run with sudo: sudo python sniffer.py")
        sys.exit(1)
    
    sniffer = PacketSniffer(interface=args.interface, config_file=args.config)
    sniffer.start_sniffing(count=args.count, verbose=args.verbose)

if __name__ == "__main__":
    import os
    main()