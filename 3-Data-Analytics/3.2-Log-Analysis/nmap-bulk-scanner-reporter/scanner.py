#!/usr/bin/env python3
"""
Nmap Bulk Scanner and Reporter
Author: Giovanni Oliveira
Description: Network scanning and vulnerability assessment tool with comprehensive reporting
"""

import os
import sys
import json
import yaml
import argparse
import logging
import time
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Any, Tuple

try:
    import nmap
except ImportError:
    print("Error: python-nmap not installed. Run: pip install python-nmap")
    sys.exit(1)

try:
    import pandas as pd
    import matplotlib.pyplot as plt
    import seaborn as sns
    HAS_VISUALIZATION = True
except ImportError:
    HAS_VISUALIZATION = False
    print("Warning: Visualization packages not installed. HTML reports will have limited graphics.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('nmap_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NmapScanner:
    """Network scanner using Nmap with comprehensive reporting capabilities"""
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize scanner with configuration"""
        self.config = self._load_config(config_file)
        self.nm = nmap.PortScanner()
        self.scan_results = {}
        self.stats = {
            'start_time': datetime.now(),
            'end_time': None,
            'total_hosts': 0,
            'hosts_up': 0,
            'hosts_down': 0,
            'total_ports': 0,
            'open_ports': 0,
            'closed_ports': 0,
            'filtered_ports': 0
        }
    
    def _load_config(self, config_file: Optional[str]) -> Dict:
        """Load configuration from YAML file"""
        if not config_file or not Path(config_file).exists():
            logger.warning("No config file provided or file not found, using defaults")
            return self._default_config()
        
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from {config_file}")
            return config
        except Exception as e:
            logger.error(f"Failed to load config file {config_file}: {e}")
            return self._default_config()
    
    def _default_config(self) -> Dict:
        """Return default configuration"""
        return {
            'scanner': {
                'threads': 4,
                'timeout': 300,
                'retries': 2
            },
            'scan_profiles': {
                'quick': {
                    'ports': 'top1000',
                    'timing': 4,
                    'scripts': 'default'
                },
                'comprehensive': {
                    'ports': '1-65535',
                    'timing': 3,
                    'scripts': 'default,vuln'
                },
                'stealth': {
                    'ports': 'top100',
                    'timing': 2,
                    'scripts': 'default',
                    'options': '-sS'
                }
            },
            'reporting': {
                'formats': ['html', 'json', 'csv'],
                'output_dir': 'reports',
                'include_screenshots': False,
                'vulnerability_lookup': True
            }
        }
    
    def scan_target(self, target: str, scan_type: str = 'quick', ports: Optional[str] = None) -> Dict:
        """Scan a single target with specified options"""
        logger.info(f"Starting scan of {target} with profile: {scan_type}")
        
        # Get scan profile from config
        profile = self.config.get('scan_profiles', {}).get(scan_type, {})
        if not profile:
            logger.warning(f"Scan profile '{scan_type}' not found, using 'quick' profile")
            profile = self.config.get('scan_profiles', {}).get('quick', {})
        
        # Build scan arguments
        scan_ports = ports or profile.get('ports', 'top1000')
        scan_timing = profile.get('timing', 4)
        scan_scripts = profile.get('scripts', 'default')
        scan_options = profile.get('options', '')
        
        # Prepare scan arguments
        args = f"-T{scan_timing} {scan_options}"
        
        if scan_scripts:
            args += f" --script={scan_scripts}"
        
        # Convert port specification
        if scan_ports == 'all':
            scan_ports = '1-65535'
        elif scan_ports == 'top1000':
            scan_ports = 'top1000'
        elif scan_ports == 'top100':
            scan_ports = 'top100'
        
        try:
            start_time = time.time()
            logger.debug(f"Running nmap with args: {args} on ports {scan_ports}")
            
            # Run the scan
            self.nm.scan(hosts=target, ports=scan_ports, arguments=args)
            
            end_time = time.time()
            scan_duration = end_time - start_time
            
            # Process results
            scan_info = self.nm.scaninfo()
            scan_stats = self.nm.scanstats()
            
            # Collect results for each host
            hosts_results = {}
            
            for host in self.nm.all_hosts():
                host_data = {
                    'status': self.nm[host].state(),
                    'hostnames': self.nm[host].hostnames(),
                    'addresses': self.nm[host].addresses(),
                    'vendor': self.nm[host].vendor() if hasattr(self.nm[host], 'vendor') else {},
                    'uptime': self.nm[host].uptime() if hasattr(self.nm[host], 'uptime') else {},
                    'tcp': {},
                    'udp': {},
                    'os': self.nm[host].get('osmatch', []) if 'osmatch' in self.nm[host] else []
                }
                
                # Get TCP ports
                if 'tcp' in self.nm[host]:
                    for port, port_data in self.nm[host]['tcp'].items():
                        host_data['tcp'][port] = port_data
                
                # Get UDP ports
                if 'udp' in self.nm[host]:
                    for port, port_data in self.nm[host]['udp'].items():
                        host_data['udp'][port] = port_data
                
                # Get script output
                if 'scripts' in self.nm[host]:
                    host_data['scripts'] = self.nm[host]['scripts']
                
                hosts_results[host] = host_data
            
            # Compile final results
            result = {
                'scan_info': scan_info,
                'scan_stats': scan_stats,
                'hosts': hosts_results,
                'scan_duration': scan_duration,
                'scan_time': datetime.now().isoformat(),
                'scan_type': scan_type,
                'target': target,
                'arguments': args
            }
            
            logger.info(f"Scan of {target} completed in {scan_duration:.2f} seconds")
            return result
            
        except nmap.PortScannerError as e:
            logger.error(f"Nmap scan error: {e}")
            return {
                'error': str(e),
                'scan_time': datetime.now().isoformat(),
                'scan_type': scan_type,
                'target': target,
                'arguments': args
            }
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
            return {
                'error': str(e),
                'scan_time': datetime.now().isoformat(),
                'scan_type': scan_type,
                'target': target,
                'arguments': args
            }
    
    def bulk_scan(self, targets: List[str], scan_type: str = 'quick', ports: Optional[str] = None) -> Dict:
        """Scan multiple targets in parallel"""
        logger.info(f"Starting bulk scan of {len(targets)} targets")
        
        # Get thread count from config
        threads = self.config.get('scanner', {}).get('threads', 4)
        
        results = {}
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # Submit scan tasks
            future_to_target = {
                executor.submit(self.scan_target, target, scan_type, ports): target
                for target in targets
            }
            
            # Collect results as they complete
            for future in future_to_target:
                target = future_to_target[future]
                try:
                    result = future.result()
                    results[target] = result
                    logger.info(f"Scan completed for {target}")
                except Exception as e:
                    logger.error(f"Error scanning {target}: {e}")
                    results[target] = {'error': str(e)}
        
        end_time = time.time()
        total_duration = end_time - start_time
        
        # Update statistics
        self.scan_results = results
        self.stats['end_time'] = datetime.now()
        self._calculate_statistics()
        
        logger.info(f"Bulk scan completed in {total_duration:.2f} seconds")
        return results
    
    def _calculate_statistics(self):
        """Calculate overall scan statistics"""
        total_hosts = 0
        hosts_up = 0
        hosts_down = 0
        total_ports = 0
        open_ports = 0
        closed_ports = 0
        filtered_ports = 0
        
        for target, result in self.scan_results.items():
            if 'error' in result:
                continue
                
            hosts = result.get('hosts', {})
            total_hosts += len(hosts)
            
            for host, host_data in hosts.items():
                if host_data.get('status') == 'up':
                    hosts_up += 1
                else:
                    hosts_down += 1
                
                # Count TCP ports
                tcp_ports = host_data.get('tcp', {})
                total_ports += len(tcp_ports)
                
                for port, port_data in tcp_ports.items():
                    if port_data.get('state') == 'open':
                        open_ports += 1
                    elif port_data.get('state') == 'closed':
                        closed_ports += 1
                    elif port_data.get('state') == 'filtered':
                        filtered_ports += 1
                
                # Count UDP ports
                udp_ports = host_data.get('udp', {})
                total_ports += len(udp_ports)
                
                for port, port_data in udp_ports.items():
                    if port_data.get('state') == 'open':
                        open_ports += 1
                    elif port_data.get('state') == 'closed':
                        closed_ports += 1
                    elif port_data.get('state') == 'filtered':
                        filtered_ports += 1
        
        self.stats['total_hosts'] = total_hosts
        self.stats['hosts_up'] = hosts_up
        self.stats['hosts_down'] = hosts_down
        self.stats['total_ports'] = total_ports
        self.stats['open_ports'] = open_ports
        self.stats['closed_ports'] = closed_ports
        self.stats['filtered_ports'] = filtered_ports
    
    def generate_report(self, output_file: Optional[str] = None, formats: Optional[List[str]] = None) -> Dict:
        """Generate reports in specified formats"""
        if not formats:
            formats = self.config.get('reporting', {}).get('formats', ['json'])
        
        if not output_file:
            output_file = f"nmap_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Create output directory if it doesn't exist
        output_dir = self.config.get('reporting', {}).get('output_dir', 'reports')
        os.makedirs(output_dir, exist_ok=True)
        
        report_files = {}
        
        # Prepare report data
        report_data = {
            'scan_results': self.scan_results,
            'statistics': self.stats,
            'generation_time': datetime.now().isoformat(),
            'scanner_version': nmap.__version__
        }
        
        # Generate reports in each format
        for fmt in formats:
            if fmt.lower() == 'json':
                report_file = os.path.join(output_dir, f"{output_file}.json")
                self._generate_json_report(report_data, report_file)
                report_files['json'] = report_file
            
            elif fmt.lower() == 'csv':
                report_file = os.path.join(output_dir, f"{output_file}.csv")
                self._generate_csv_report(report_data, report_file)
                report_files['csv'] = report_file
            
            elif fmt.lower() == 'html':
                report_file = os.path.join(output_dir, f"{output_file}.html")
                self._generate_html_report(report_data, report_file)
                report_files['html'] = report_file
            
            elif fmt.lower() == 'xml':
                report_file = os.path.join(output_dir, f"{output_file}.xml")
                self._generate_xml_report(report_data, report_file)
                report_files['xml'] = report_file
            
            else:
                logger.warning(f"Unsupported report format: {fmt}")
        
        logger.info(f"Reports generated: {', '.join(report_files.keys())}")
        return report_files
    
    def _generate_json_report(self, data: Dict, output_file: str) -> None:
        """Generate JSON report"""
        try:
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            logger.info(f"JSON report saved to {output_file}")
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
    
    def _generate_csv_report(self, data: Dict, output_file: str) -> None:
        """Generate CSV report"""
        try:
            # Flatten scan results for CSV format
            csv_data = []
            
            for target, result in data['scan_results'].items():
                if 'error' in result:
                    csv_data.append({
                        'target': target,
                        'status': 'error',
                        'error': result['error'],
                        'scan_time': result.get('scan_time', ''),
                        'scan_type': result.get('scan_type', '')
                    })
                    continue
                
                hosts = result.get('hosts', {})
                
                for host, host_data in hosts.items():
                    # Process TCP ports
                    for port, port_data in host_data.get('tcp', {}).items():
                        csv_data.append({
                            'target': target,
                            'host': host,
                            'status': host_data.get('status', ''),
                            'protocol': 'tcp',
                            'port': port,
                            'state': port_data.get('state', ''),
                            'service': port_data.get('name', ''),
                            'version': port_data.get('product', ''),
                            'scan_time': result.get('scan_time', ''),
                            'scan_type': result.get('scan_type', '')
                        })
                    
                    # Process UDP ports
                    for port, port_data in host_data.get('udp', {}).items():
                        csv_data.append({
                            'target': target,
                            'host': host,
                            'status': host_data.get('status', ''),
                            'protocol': 'udp',
                            'port': port,
                            'state': port_data.get('state', ''),
                            'service': port_data.get('name', ''),
                            'version': port_data.get('product', ''),
                            'scan_time': result.get('scan_time', ''),
                            'scan_type': result.get('scan_type', '')
                        })
            
            # Write to CSV
            if csv_data:
                with open(output_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=csv_data[0].keys())
                    writer.writeheader()
                    writer.writerows(csv_data)
                logger.info(f"CSV report saved to {output_file}")
            else:
                logger.warning("No data to write to CSV report")
        
        except Exception as e:
            logger.error(f"Error generating CSV report: {e}")
    
    def _generate_html_report(self, data: Dict, output_file: str) -> None:
        """Generate HTML report"""
        try:
            # Basic HTML template
            html_template = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Nmap Scan Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }
                    h1, h2, h3, h4 { color: #2c3e50; }
                    .container { max-width: 1200px; margin: 0 auto; }
                    .header { background-color: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; }
                    .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
                    .stats { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 20px; }
                    .stat-card { background-color: #fff; border: 1px solid #ddd; border-radius: 5px; padding: 15px; flex: 1; min-width: 200px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                    .host { background-color: #fff; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                    .host-header { display: flex; justify-content: space-between; align-items: center; }
                    .host-up { border-left: 5px solid #28a745; }
                    .host-down { border-left: 5px solid #dc3545; }
                    table { width: 100%; border-collapse: collapse; margin-bottom: 15px; }
                    th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
                    th { background-color: #f2f2f2; }
                    tr:hover { background-color: #f5f5f5; }
                    .port-open { color: #28a745; font-weight: bold; }
                    .port-closed { color: #dc3545; }
                    .port-filtered { color: #ffc107; }
                    .footer { margin-top: 30px; text-align: center; font-size: 0.8em; color: #6c757d; }
                    .chart { margin: 20px 0; height: 300px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Nmap Network Scan Report</h1>
                        <p>Generated on: {generation_time}</p>
                    </div>
                    
                    <div class="summary">
                        <h2>Scan Summary</h2>
                        <p>Scan started at {start_time} and completed at {end_time}.</p>
                        <p>Total scan duration: {scan_duration} minutes</p>
                    </div>
                    
                    <div class="stats">
                        <div class="stat-card">
                            <h3>Hosts</h3>
                            <p>Total: {total_hosts}</p>
                            <p>Up: {hosts_up}</p>
                            <p>Down: {hosts_down}</p>
                        </div>
                        <div class="stat-card">
                            <h3>Ports</h3>
                            <p>Total: {total_ports}</p>
                            <p>Open: {open_ports}</p>
                            <p>Closed: {closed_ports}</p>
                            <p>Filtered: {filtered_ports}</p>
                        </div>
                        <div class="stat-card">
                            <h3>Services</h3>
                            <p>Total unique services: {unique_services}</p>
                            <p>Top service: {top_service}</p>
                        </div>
                    </div>
                    
                    <h2>Scan Results</h2>
                    
                    {host_results}
                    
                    <div class="footer">
                        <p>Generated by Nmap Bulk Scanner and Reporter v1.0</p>
                        <p>Author: Giovanni Oliveira</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Calculate statistics
            start_time = data['statistics']['start_time']
            end_time = data['statistics']['end_time'] or datetime.now()
            scan_duration = (end_time - start_time).total_seconds() / 60
            
            # Count unique services
            services = []
            service_counts = {}
            
            # Process host results
            host_results_html = ""
            
            for target, result in data['scan_results'].items():
                if 'error' in result:
                    host_results_html += f"""
                    <div class="host host-down">
                        <div class="host-header">
                            <h3>Target: {target}</h3>
                            <span>Error</span>
                        </div>
                        <p>Error: {result['error']}</p>
                    </div>
                    """
                    continue
                
                hosts = result.get('hosts', {})
                
                for host, host_data in hosts.items():
                    status = host_data.get('status', 'unknown')
                    host_class = "host-up" if status == "up" else "host-down"
                    
                    host_results_html += f"""
                    <div class="host {host_class}">
                        <div class="host-header">
                            <h3>Host: {host}</h3>
                            <span>Status: {status}</span>
                        </div>
                    """
                    
                    # Add hostnames
                    hostnames = host_data.get('hostnames', [])
                    if hostnames:
                        host_results_html += "<p><strong>Hostnames:</strong> "
                        host_results_html += ", ".join([h.get('name', '') for h in hostnames])
                        host_results_html += "</p>"
                    
                    # Add OS detection results
                    os_matches = host_data.get('os', [])
                    if os_matches:
                        host_results_html += "<p><strong>OS Detection:</strong> "
                        os_names = [os_match.get('name', '') for os_match in os_matches[:3]]
                        host_results_html += ", ".join(os_names)
                        host_results_html += "</p>"
                    
                    # Add TCP ports
                    tcp_ports = host_data.get('tcp', {})
                    if tcp_ports:
                        host_results_html += """
                        <h4>TCP Ports</h4>
                        <table>
                            <tr>
                                <th>Port</th>
                                <th>State</th>
                                <th>Service</th>
                                <th>Version</th>
                            </tr>
                        """
                        
                        for port, port_data in sorted(tcp_ports.items()):
                            state = port_data.get('state', '')
                            state_class = f"port-{state}" if state in ['open', 'closed', 'filtered'] else ""
                            service = port_data.get('name', '')
                            product = port_data.get('product', '')
                            version = port_data.get('version', '')
                            
                            # Collect service statistics
                            if state == 'open' and service:
                                services.append(service)
                                service_counts[service] = service_counts.get(service, 0) + 1
                            
                            host_results_html += f"""
                            <tr>
                                <td>{port}/tcp</td>
                                <td class="{state_class}">{state}</td>
                                <td>{service}</td>
                                <td>{product} {version}</td>
                            </tr>
                            """
                        
                        host_results_html += "</table>"
                    
                    # Add UDP ports
                    udp_ports = host_data.get('udp', {})
                    if udp_ports:
                        host_results_html += """
                        <h4>UDP Ports</h4>
                        <table>
                            <tr>
                                <th>Port</th>
                                <th>State</th>
                                <th>Service</th>
                                <th>Version</th>
                            </tr>
                        """
                        
                        for port, port_data in sorted(udp_ports.items()):
                            state = port_data.get('state', '')
                            state_class = f"port-{state}" if state in ['open', 'closed', 'filtered'] else ""
                            service = port_data.get('name', '')
                            product = port_data.get('product', '')
                            version = port_data.get('version', '')
                            
                            # Collect service statistics
                            if state == 'open' and service:
                                services.append(service)
                                service_counts[service] = service_counts.get(service, 0) + 1
                            
                            host_results_html += f"""
                            <tr>
                                <td>{port}/udp</td>
                                <td class="{state_class}">{state}</td>
                                <td>{service}</td>
                                <td>{product} {version}</td>
                            </tr>
                            """
                        
                        host_results_html += "</table>"
                    
                    # Add script output
                    scripts = host_data.get('scripts', {})
                    if scripts:
                        host_results_html += "<h4>Script Results</h4>"
                        
                        for script_name, script_output in scripts.items():
                            host_results_html += f"""
                            <div>
                                <h5>{script_name}</h5>
                                <pre>{script_output}</pre>
                            </div>
                            """
                    
                    host_results_html += "</div>"
            
            # Calculate service statistics
            unique_services = len(set(services))
            top_service = max(service_counts.items(), key=lambda x: x[1])[0] if service_counts else "None"
            
            # Fill in template
            html_content = html_template.format(
                generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                start_time=start_time.strftime("%Y-%m-%d %H:%M:%S"),
                end_time=end_time.strftime("%Y-%m-%d %H:%M:%S"),
                scan_duration=f"{scan_duration:.2f}",
                total_hosts=data['statistics']['total_hosts'],
                hosts_up=data['statistics']['hosts_up'],
                hosts_down=data['statistics']['hosts_down'],
                total_ports=data['statistics']['total_ports'],
                open_ports=data['statistics']['open_ports'],
                closed_ports=data['statistics']['closed_ports'],
                filtered_ports=data['statistics']['filtered_ports'],
                unique_services=unique_services,
                top_service=top_service,
                host_results=host_results_html
            )
            
            # Write HTML report
            with open(output_file, 'w') as f:
                f.write(html_content)
            
            logger.info(f"HTML report saved to {output_file}")
            
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
    
    def _generate_xml_report(self, data: Dict, output_file: str) -> None:
        """Generate XML report"""
        try:
            # Create XML structure
            root = ET.Element("nmaprun")
            root.set("scanner", "nmap")
            root.set("start", str(int(data['statistics']['start_time'].timestamp())))
            root.set("version", data.get('scanner_version', ''))
            
            # Add scan info
            scaninfo = ET.SubElement(root, "scaninfo")
            
            # Add statistics
            stats = ET.SubElement(root, "statistics")
            hosts = ET.SubElement(stats, "hosts")
            hosts.set("up", str(data['statistics']['hosts_up']))
            hosts.set("down", str(data['statistics']['hosts_down']))
            hosts.set("total", str(data['statistics']['total_hosts']))
            
            # Add host information
            for target, result in data['scan_results'].items():
                if 'error' in result:
                    continue
                
                hosts_data = result.get('hosts', {})
                
                for host_ip, host_data in hosts_data.items():
                    host_elem = ET.SubElement(root, "host")
                    host_elem.set("starttime", str(int(datetime.fromisoformat(result.get('scan_time', datetime.now().isoformat())).timestamp())))
                    
                    # Add status
                    status = ET.SubElement(host_elem, "status")
                    status.set("state", host_data.get('status', 'unknown'))
                    
                    # Add address
                    address = ET.SubElement(host_elem, "address")
                    address.set("addr", host_ip)
                    address.set("addrtype", "ipv4")
                    
                    # Add hostnames
                    hostnames_elem = ET.SubElement(host_elem, "hostnames")
                    for hostname in host_data.get('hostnames', []):
                        hostname_elem = ET.SubElement(hostnames_elem, "hostname")
                        hostname_elem.set("name", hostname.get('name', ''))
                        hostname_elem.set("type", hostname.get('type', ''))
                    
                    # Add ports
                    ports_elem = ET.SubElement(host_elem, "ports")
                    
                    # TCP ports
                    for port, port_data in host_data.get('tcp', {}).items():
                        port_elem = ET.SubElement(ports_elem, "port")
                        port_elem.set("protocol", "tcp")
                        port_elem.set("portid", str(port))
                        
                        state_elem = ET.SubElement(port_elem, "state")
                        state_elem.set("state", port_data.get('state', ''))
                        
                        service_elem = ET.SubElement(port_elem, "service")
                        service_elem.set("name", port_data.get('name', ''))
                        service_elem.set("product", port_data.get('product', ''))
                        service_elem.set("version", port_data.get('version', ''))
                    
                    # UDP ports
                    for port, port_data in host_data.get('udp', {}).items():
                        port_elem = ET.SubElement(ports_elem, "port")
                        port_elem.set("protocol", "udp")
                        port_elem.set("portid", str(port))
                        
                        state_elem = ET.SubElement(port_elem, "state")
                        state_elem.set("state", port_data.get('state', ''))
                        
                        service_elem = ET.SubElement(port_elem, "service")
                        service_elem.set("name", port_data.get('name', ''))
                        service_elem.set("product", port_data.get('product', ''))
                        service_elem.set("version", port_data.get('version', ''))
                    
                    # Add OS detection
                    os_elem = ET.SubElement(host_elem, "os")
                    for os_match in host_data.get('os', []):
                        osmatch_elem = ET.SubElement(os_elem, "osmatch")
                        osmatch_elem.set("name", os_match.get('name', ''))
                        osmatch_elem.set("accuracy", str(os_match.get('accuracy', '')))
            
            # Write XML to file
            tree = ET.ElementTree(root)
            tree.write(output_file, encoding='utf-8', xml_declaration=True)
            
            logger.info(f"XML report saved to {output_file}")
            
        except Exception as e:
            logger.error(f"Error generating XML report: {e}")
    
    def analyze_vulnerabilities(self) -> Dict:
        """Analyze scan results for potential vulnerabilities"""
        vulnerabilities = []
        
        # Common vulnerable services and versions
        vulnerable_services = {
            'http': ['Apache/2.4.49', 'Apache/2.4.50', 'nginx/1.18.0'],
            'ssh': ['OpenSSH 7.', 'OpenSSH 6.'],
            'smb': ['Samba 3.', 'Samba 4.1'],
            'ftp': ['vsftpd 2.3.4', 'ProFTPD 1.3.5'],
            'telnet': ['*'],  # Any telnet service is potentially vulnerable
            'rdp': ['*']      # Any RDP service is potentially vulnerable
        }
        
        for target, result in self.scan_results.items():
            if 'error' in result:
                continue
                
            hosts = result.get('hosts', {})
            
            for host, host_data in hosts.items():
                # Check TCP ports
                for port, port_data in host_data.get('tcp', {}).items():
                    if port_data.get('state') != 'open':
                        continue
                    
                    service = port_data.get('name', '').lower()
                    product = port_data.get('product', '')
                    version = port_data.get('version', '')
                    
                    # Check for known vulnerable services
                    if service in vulnerable_services:
                        patterns = vulnerable_services[service]
                        
                        for pattern in patterns:
                            if pattern == '*' or (product and pattern in product + ' ' + version):
                                vulnerabilities.append({
                                    'host': host,
                                    'port': port,
                                    'protocol': 'tcp',
                                    'service': service,
                                    'version': f"{product} {version}".strip(),
                                    'severity': 'high' if service in ['telnet', 'ftp'] else 'medium',
                                    'description': f"Potentially vulnerable {service} service detected",
                                    'recommendation': f"Upgrade {service} to the latest version or disable if not needed"
                                })
                    
                    # Check for dangerous ports
                    if port in [21, 23, 445, 3389]:
                        severity = 'high' if port in [23, 445] else 'medium'
                        vulnerabilities.append({
                            'host': host,
                            'port': port,
                            'protocol': 'tcp',
                            'service': service,
                            'version': f"{product} {version}".strip(),
                            'severity': severity,
                            'description': f"Potentially risky service {service} running on port {port}",
                            'recommendation': f"Consider disabling {service} if not required"
                        })
        
        return {
            'vulnerabilities': vulnerabilities,
            'total_count': len(vulnerabilities),
            'severity_counts': {
                'critical': len([v for v in vulnerabilities if v['severity'] == 'critical']),
                'high': len([v for v in vulnerabilities if v['severity'] == 'high']),
                'medium': len([v for v in vulnerabilities if v['severity'] == 'medium']),
                'low': len([v for v in vulnerabilities if v['severity'] == 'low'])
            }
        }

def main():
    """Main function with command-line interface"""
    parser = argparse.ArgumentParser(description="Nmap Bulk Scanner and Reporter")
    
    parser.add_argument('--target', '-t', nargs='+', help='Target IP, range, or network (e.g., 192.168.1.0/24)')
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--scan-type', choices=['quick', 'comprehensive', 'stealth', 'vuln'], default='quick', help='Scan type')
    parser.add_argument('--ports', help='Port specification (e.g., 22,80,443 or 1-1000)')
    parser.add_argument('--output', '-o', help='Output file base name')
    parser.add_argument('--format', '-f', nargs='+', choices=['json', 'csv', 'html', 'xml'], default=['json'], help='Report format')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize scanner
    scanner = NmapScanner(args.config)
    
    # Get targets from arguments or config
    targets = args.target
    if not targets:
        targets = scanner.config.get('targets', {}).get('networks', [])
        if not targets:
            logger.error("No targets specified. Use --target or configure targets in config file.")
            sys.exit(1)
    
    # Run scan
    results = scanner.bulk_scan(targets, args.scan_type, args.ports)
    
    # Generate vulnerability analysis
    vuln_analysis = scanner.analyze_vulnerabilities()
    logger.info(f"Identified {vuln_analysis['total_count']} potential vulnerabilities")
    
    # Generate reports
    report_files = scanner.generate_report(args.output, args.format)
    
    # Print summary
    print("\nScan Summary:")
    print(f"Targets scanned: {len(targets)}")
    print(f"Hosts discovered: {scanner.stats['total_hosts']}")
    print(f"Hosts up: {scanner.stats['hosts_up']}")
    print(f"Open ports found: {scanner.stats['open_ports']}")
    print(f"Potential vulnerabilities: {vuln_analysis['total_count']}")
    print("\nReports generated:")
    for fmt, file_path in report_files.items():
        print(f"- {fmt.upper()}: {file_path}")

if __name__ == '__main__':
    main()