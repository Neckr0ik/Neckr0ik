#!/usr/bin/env python3
"""
Unit tests for the packet sniffer module
Author: Giovanni Oliveira
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import json
import tempfile
import os

# Import the sniffer module
from sniffer import PacketSniffer

class TestPacketSniffer(unittest.TestCase):
    """Test cases for PacketSniffer class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config_data = {
            "suspicious_ports": [22, 23, 135],
            "max_connections_per_ip": 50,
            "scan_threshold": 5,
            "log_level": "INFO",
            "output_file": "test_output.log"
        }
        
        # Create temporary config file
        self.temp_config = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(self.config_data, self.temp_config)
        self.temp_config.close()
        
        self.sniffer = PacketSniffer(interface="test0", config_file=self.temp_config.name)
    
    def tearDown(self):
        """Clean up test fixtures."""
        os.unlink(self.temp_config.name)
        if os.path.exists("test_output.log"):
            os.unlink("test_output.log")
    
    def test_load_config(self):
        """Test configuration loading."""
        self.assertEqual(self.sniffer.config["suspicious_ports"], [22, 23, 135])
        self.assertEqual(self.sniffer.config["scan_threshold"], 5)
    
    def test_default_config(self):
        """Test default configuration when file doesn't exist."""
        sniffer = PacketSniffer(config_file="nonexistent.json")
        self.assertIn("suspicious_ports", sniffer.config)
        self.assertIsInstance(sniffer.config["suspicious_ports"], list)
    
    def test_detect_port_scan(self):
        """Test port scan detection logic."""
        test_ip = "192.168.1.100"
        
        # Simulate multiple port accesses
        for port in range(80, 90):
            self.sniffer.detect_port_scan(test_ip, port)
        
        # Should detect port scan after threshold
        self.assertIn(test_ip, self.sniffer.suspicious_ips)
        self.assertEqual(len(self.sniffer.port_scan_attempts[test_ip]), 10)
    
    @patch('sniffer.IP')
    @patch('sniffer.TCP')
    def test_is_suspicious_port(self, mock_tcp, mock_ip):
        """Test suspicious port detection."""
        # Create mock packet
        mock_packet = Mock()
        mock_packet.__contains__ = lambda self, key: key == mock_tcp
        mock_packet.__getitem__ = lambda self, key: Mock(dport=22)
        
        result = self.sniffer.is_suspicious_port(mock_packet)
        self.assertTrue(result)
    
    def test_packet_count_increment(self):
        """Test packet counting functionality."""
        initial_count = self.sniffer.packet_count
        
        # Create mock packet with IP layer
        mock_packet = Mock()
        mock_packet.__contains__ = lambda self, key: key.__name__ == 'IP'
        mock_packet.__getitem__ = lambda self, key: Mock(src="192.168.1.1", dst="192.168.1.2")
        
        self.sniffer.analyze_packet(mock_packet)
        self.assertEqual(self.sniffer.packet_count, initial_count + 1)

if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)