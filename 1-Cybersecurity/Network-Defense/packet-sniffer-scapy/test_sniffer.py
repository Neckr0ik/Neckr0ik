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
    
    def test_suspicious_ip_tracking(self):
        """Test suspicious IP address tracking."""
        test_ip = "10.0.0.1"
        
        # Add IP to suspicious list
        self.sniffer.suspicious_ips.add(test_ip)
        
        self.assertIn(test_ip, self.sniffer.suspicious_ips)
        self.assertEqual(len(self.sniffer.suspicious_ips), 1)
    
    @patch('sniffer.logging')
    def test_logging_setup(self, mock_logging):
        """Test logging configuration."""
        sniffer = PacketSniffer()
        mock_logging.basicConfig.assert_called()
    
    def test_generate_report_with_suspicious_ips(self):
        """Test report generation with suspicious IPs."""
        # Add some test data
        self.sniffer.packet_count = 100
        self.sniffer.suspicious_ips.add("192.168.1.100")
        self.sniffer.suspicious_ips.add("10.0.0.1")
        
        # Mock logger to capture output
        with patch.object(self.sniffer, 'logger') as mock_logger:
            self.sniffer.generate_report()
            
            # Verify report content
            mock_logger.info.assert_called()
            mock_logger.warning.assert_called()
    
    def test_generate_report_no_threats(self):
        """Test report generation with no threats detected."""
        self.sniffer.packet_count = 50
        
        with patch.object(self.sniffer, 'logger') as mock_logger:
            self.sniffer.generate_report()
            
            # Should log basic statistics
            mock_logger.info.assert_called()

class TestPacketAnalysis(unittest.TestCase):
    """Test cases for packet analysis functionality."""
    
    def setUp(self):
        """Set up test fixtures for packet analysis."""
        self.sniffer = PacketSniffer()
    
    @patch('sniffer.IP')
    @patch('sniffer.TCP')
    def test_tcp_packet_analysis(self, mock_tcp, mock_ip):
        """Test TCP packet analysis."""
        # Create mock TCP packet
        mock_packet = Mock()
        mock_packet.__contains__ = lambda self, key: key in [mock_ip, mock_tcp]
        
        ip_mock = Mock()
        ip_mock.src = "192.168.1.1"
        ip_mock.dst = "192.168.1.2"
        
        tcp_mock = Mock()
        tcp_mock.dport = 80
        tcp_mock.sport = 12345
        
        mock_packet.__getitem__ = lambda self, key: ip_mock if key == mock_ip else tcp_mock
        
        initial_count = self.sniffer.packet_count
        self.sniffer.analyze_packet(mock_packet)
        
        self.assertEqual(self.sniffer.packet_count, initial_count + 1)
    
    def test_port_scan_threshold(self):
        """Test port scan detection threshold."""
        test_ip = "192.168.1.50"
        threshold = self.sniffer.config["scan_threshold"]
        
        # Access ports below threshold
        for port in range(80, 80 + threshold - 1):
            self.sniffer.detect_port_scan(test_ip, port)
        
        # Should not be flagged yet
        self.assertNotIn(test_ip, self.sniffer.suspicious_ips)
        
        # Access one more port to exceed threshold
        self.sniffer.detect_port_scan(test_ip, 80 + threshold)
        
        # Should now be flagged
        self.assertIn(test_ip, self.sniffer.suspicious_ips)

if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)