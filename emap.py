#!/usr/bin/env python3

import argparse
import socket
import threading
import os
import time
import json
from typing import List, Dict, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
import errno
from functools import partial
import random
from colorama import init, Fore, Style
import re

class EMAP:
    def __init__(self):
        self.target: str = ""
        self.ports: List[int] = []
        self.scan_type: str = "tcp"
        self.output_format: str = "txt"
        self.results: Dict[int, Dict[str, Union[bool, str]]] = {}
        self.threads: int = 100  # Default number of threads
        self.verbose: bool = False
        self.timeout: float = 1.0
        self.timing: str = "normal"
        self.no_ping: bool = False
        self.aggressive: bool = False
        
        # Timing templates (seconds)
        self.timing_templates = {
            'paranoid':   {'timeout': 5.0,  'delay': 0.5},
            'sneaky':     {'timeout': 3.0,  'delay': 0.3},
            'polite':     {'timeout': 2.0,  'delay': 0.2},
            'normal':     {'timeout': 1.0,  'delay': 0.1},
            
            'aggressive': {'timeout': 0.5,  'delay': 0.05},
            'insane':     {'timeout': 0.25, 'delay': 0.0}
        }
        
        # Add common ports dictionary with their typical services
        self.common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPC",
            135: "MSRPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1723: "PPTP",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt"
        }
        
        # Add service signatures database
        self.service_signatures = {
            'HTTP': {
                'Apache': [
                    r'Apache/([\d.]+)',
                    r'Apache\s+Version\s+([0-9.]+)',
                    r'Apache[^/]*?/([0-9.]+)',
                ],
                'nginx': [
                    r'nginx/([\d.]+)',
                    r'nginx\s+version:\s+nginx/([0-9.]+)',
                ],
                'IIS': [
                    r'Microsoft-IIS/([\d.]+)',
                    r'IIS/([\d.]+)',
                ],
                'lighttpd': [
                    r'lighttpd/([\d.]+)',
                ],
                'PHP': [
                    r'PHP/([\d.]+)',
                    r'X-Powered-By: PHP/([\d.]+)',
                ]
            },
            'SSH': {
                'OpenSSH': [
                    r'OpenSSH[_-]([\d.]+\w*)',
                    r'SSH-2.0-OpenSSH[_-]([\d.]+\w*)',
                ],
                'Dropbear': [
                    r'dropbear_([\d.]+)',
                ]
            },
            'FTP': {
                'vsftpd': [
                    r'vsftpd\s+([\d.]+)',
                    r'\(vsFTPd\s+([\d.]+)\)',
                ],
                'ProFTPD': [
                    r'ProFTPD\s+([\d.]+)',
                    r'ProFTPD Server \(Ver. ([\d.]+)\)',
                ],
                'Pure-FTPd': [
                    r'Pure-FTPd[- ]([\d.]+)',
                ],
                'FileZilla': [
                    r'FileZilla Server[/ ]([\d.]+)',
                ]
            },
            'SMTP': {
                'Postfix': [
                    r'Postfix[/ ]([\d.]+)',
                    r'ESMTP Postfix[/ ]([\d.]+)',
                ],
                'Exim': [
                    r'Exim[/ ]([\d.]+)',
                ],
                'Sendmail': [
                    r'Sendmail[/ ]([\d.]+)',
                ],
                'Microsoft Exchange': [
                    r'Microsoft ESMTP MAIL Service[^0-9]*([\d.]+)',
                ]
            },
            'MySQL': {
                'MySQL': [
                    r'MySQL[/ ]([\d.]+)',
                    r'(\d+\.\d+\.\d+)-MariaDB',
                    r'(\d+\.\d+\.\d+)-MySQL',
                ]
            },
            'PostgreSQL': {
                'PostgreSQL': [
                    r'PostgreSQL ([\d.]+)',
                    r'postgres[/ ]([\d.]+)',
                ]
            }
        }

    def parse_arguments(self) -> None:
        """Parse command line arguments."""
        parser = argparse.ArgumentParser(
            description='''
EMAP - Extended Map Port Scanner
A fast, multi-threaded port scanner with service detection and banner grabbing.

Basic Usage:
    emap.py -t <target>
        ''',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
Arguments:
  -t,  --target    Target IP address or hostname (required)
  -p,  --ports     Port range to scan (default: common ports only). Examples: -p 80,443,8080 or -p 1-1024
  -s,  --scan-type Type of scan: tcp, udp, syn, fin, xmas, ack (default: tcp)
  -o,  --output    Output format: txt, json, xml (default: txt)
  -A,  --aggressive Enable aggressive scanning (faster but noisier)
  -v,  --verbose   Show detailed output during scanning
  
Advanced Options:
  --threads        Number of threads to use (default: 100)
  --timing         Timing template: paranoid, sneaky, polite, normal, aggressive, insane
  --timeout        Connection timeout in seconds (default: 1.0)
  --no-ping        Skip host discovery ping

Examples:
  emap.py -t example.com                    # Scan all ports
  emap.py -t 192.168.1.1 -p 80,443,8080    # Scan specific ports
  emap.py -t example.com -s udp -p 53,161   # UDP scan
  emap.py -t example.com -A                 # Aggressive (faster) scan
  emap.py -t example.com -o json            # Output in JSON format
  emap.py -t example.com --timing sneaky    # Stealthy scan

Timing Templates:
  paranoid   - Very slow, but very stealthy
  sneaky     - Slow and stealthy
  polite     - Normal speed, less aggressive
  normal     - Default balanced settings
  aggressive - Faster, but more detectable
  insane     - Fastest, but very noisy
'''
        )
        
        # Target specification
        parser.add_argument(
            '-t', '--target',
            required=True,
            help='Target IP address or hostname'
        )
        
        # Port specification
        parser.add_argument(
            '-p', '--ports',
            default='1-65535',  # This will be interpreted as "use common ports"
            help='Port range to scan (default: common ports only). Examples: -p 80,443,8080 or -p 1-1024'
        )
        
        # Scan type
        parser.add_argument(
            '-s', '--scan-type',
            choices=['tcp', 'udp', 'syn', 'fin', 'xmas', 'ack'],
            default='tcp',
            help='Type of scan to perform'
        )
        
        # Output format
        parser.add_argument(
            '-o', '--output',
            choices=['txt', 'json', 'xml'],
            default='txt',
            help='Output format'
        )
        
        # Performance options
        parser.add_argument(
            '--threads',
            type=int,
            default=100,
            help='Number of threads to use'
        )
        
        parser.add_argument(
            '--timing',
            choices=['paranoid', 'sneaky', 'polite', 'normal', 'aggressive', 'insane'],
            default='normal',
            help='Timing template (affects scan delay and timeout)'
        )
        
        # Additional options
        parser.add_argument(
            '-v', '--verbose',
            action='store_true',
            help='Enable verbose output'
        )
        
        parser.add_argument(
            '--timeout',
            type=float,
            default=1.0,
            help='Timeout in seconds for each port scan'
        )
        
        parser.add_argument(
            '--no-ping',
            action='store_true',
            help='Skip host discovery ping'
        )
        
        # Add aggressive mode flag
        parser.add_argument(
            '-A', '--aggressive',
            action='store_true',
            help='Enable aggressive scanning (faster but may be less accurate)'
        )

        args = parser.parse_args()
        
        # Update instance variables
        self.target = args.target
        self.scan_type = args.scan_type
        self.output_format = args.output
        self.threads = args.threads
        self.verbose = args.verbose
        self.timeout = args.timeout
        self.timing = args.timing
        self.no_ping = args.no_ping
        self.aggressive = args.aggressive
        self.parse_port_range(args.ports)

    def parse_port_range(self, port_range: str) -> None:
        """Parse port range from string input."""
        try:
            # If no ports specified, use common ports
            if port_range == '1-65535':  # This is our default value
                self.ports = sorted(list(self.common_ports.keys()))
                return
            
            # Handle comma-separated ports (e.g., "80,443,8080")
            if ',' in port_range:
                self.ports = [int(port) for port in port_range.split(',')]
            # Handle range of ports (e.g., "1-1024")
            elif '-' in port_range:
                start, end = map(int, port_range.split('-'))
                self.ports = list(range(start, end + 1))
            # Handle single port
            else:
                self.ports = [int(port_range)]
        except ValueError:
            print("Error: Invalid port range format")
            exit(1)

    def validate_target(self) -> None:
        """Validate target IP address or hostname."""
        try:
            socket.gethostbyname(self.target)
        except socket.gaierror:
            print(f"Error: Could not resolve hostname {self.target}")
            exit(1)

    def _grab_banner(self, target_ip: str, port: int) -> str:
        """Service and version detection with advanced probing."""
        service = self._get_service_name(port)
        
        # Try normal banner grab first
        banner = ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((target_ip, port))
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if response:
                    banner = self._identify_service_version(service, response)
        except:
            pass
        
        # If no banner, try error-based probing
        if not banner:
            error_banner = self._error_based_probe(target_ip, port, service)
            if error_banner:
                return error_banner
        
        # If still no banner, try advanced probing
        if not banner:
            advanced_banner = self._advanced_service_probe(target_ip, port, service)
            if advanced_banner:
                return advanced_banner
        
        return banner or service

    def tcp_connect_scan(self, port: int, target_ip: str) -> None:
        """Perform a TCP Connect scan with banner grabbing."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timing_templates[self.timing]['timeout'])
            
            result = sock.connect_ex((target_ip, port))
            
            if result == 0:
                # Port is open, try to grab banner
                service = self._get_service_name(port)
                banner = self._grab_banner(target_ip, port) if not self.aggressive else ""
                
                self.results[port] = {
                    'state': 'open',
                    'service': service,
                    'banner': banner
                }
                
                if self.verbose:
                    if banner:
                        print(f"\nPort {port}/tcp is open ({service}) - {banner}")
                    else:
                        print(f"\nPort {port}/tcp is open ({service})")
            
            sock.close()
            
        except Exception as e:
            if self.verbose:
                print(f"\nError scanning port {port}/tcp: {e}")

    def _get_service_name(self, port: int) -> str:
        """Get service name for a port number."""
        # First check our common ports dictionary
        if port in self.common_ports:
            return self.common_ports[port]
        
        # Then try system service database
        try:
            return socket.getservbyport(port)
        except (socket.error, OSError):
            return "unknown"

    def _identify_service_version(self, service: str, banner: str) -> str:
        """Enhanced service and version detection."""
        if not banner:
            return ""
        
        # Enhanced version patterns for common web servers
        detailed_patterns = {
            'HTTP': {
                'nginx': [
                    # Detailed nginx patterns
                    (r'nginx/(\d+\.\d+\.\d+)', 'nginx/{0}'),
                    (r'nginx/(\d+\.\d+\.\d+)-([^\s]+)', 'nginx/{0}-{1}'),
                    (r'(nginx)\s+version:\s+nginx/(\d+\.\d+\.\d+)', '{0}/{1}')
                ],
                'Apache': [
                    # Detailed Apache patterns
                    (r'Apache/(\d+\.\d+\.\d+)\s*\(([^)]+)\)', 'Apache/{0} ({1})'),
                    (r'Apache/(\d+\.\d+\.\d+)\s+\(([^)]+)\)\s+OpenSSL/([^\s]+)', 'Apache/{0} ({1}) OpenSSL/{2}'),
                    (r'Apache/(\d+\.\d+\.\d+)\s+\(([^)]+)\)\s+PHP/([^\s]+)', 'Apache/{0} ({1}) PHP/{2}')
                ],
                'PHP': [
                    # PHP version patterns
                    (r'PHP/(\d+\.\d+\.\d+)-(\w+)', 'PHP/{0}-{1}'),
                    (r'PHP/(\d+\.\d+\.\d+)', 'PHP/{0}'),
                    (r'X-Powered-By: PHP/(\d+\.\d+\.\d+)-(\w+)', 'PHP/{0}-{1}')
                ],
                'OpenSSL': [
                    # OpenSSL version patterns
                    (r'OpenSSL/(\d+\.\d+\.\d+\w*)', 'OpenSSL/{0}'),
                    (r'OpenSSL\s+(\d+\.\d+\.\d+\w*)', 'OpenSSL/{0}')
                ]
            },
            'SSH': {
                'OpenSSH': [
                    # Detailed SSH patterns
                    (r'OpenSSH[_-](\d+\.\d+\w*)\s+([^-\s]+)-([^-\s]+)', 'OpenSSH {0} {1}-{2}'),
                    (r'OpenSSH[_-](\d+\.\d+\w*)\s+([^\s]+)', 'OpenSSH {0} {1}'),
                    (r'SSH-2\.0-OpenSSH[_-](\d+\.\d+\w*)', 'OpenSSH {0}')
                ]
            },
            'FTP': {
                'vsftpd': [
                    # vsftpd patterns
                    (r'vsftpd\s+(\d+\.\d+\.\d+)', 'vsftpd {0}'),
                    (r'\(vsFTPd\s+(\d+\.\d+\.\d+)\)', 'vsftpd {0}')
                ],
                'ProFTPD': [
                    # ProFTPD patterns
                    (r'ProFTPD\s+(\d+\.\d+\.\d+)\s+([^)]+)', 'ProFTPD {0} {1}'),
                    (r'ProFTPD\s+(\d+\.\d+\.\d+)', 'ProFTPD {0}')
                ]
            },
            'MySQL': {
                'MySQL': [
                    # MySQL patterns
                    (r'(\d+\.\d+\.\d+)-MariaDB-([^\s]+)', 'MariaDB {0}-{1}'),
                    (r'(\d+\.\d+\.\d+)-([^\s]+)\s+MariaDB', 'MariaDB {0}-{1}'),
                    (r'MySQL\s+(\d+\.\d+\.\d+)-([^\s]+)', 'MySQL {0}-{1}'),
                    (r'(\d+\.\d+\.\d+)-MySQL', 'MySQL {0}')
                ]
            }
        }

        # Try detailed patterns first
        if service in detailed_patterns:
            for software, patterns in detailed_patterns[service].items():
                for pattern, format_str in patterns:
                    match = re.search(pattern, banner, re.IGNORECASE)
                    if match:
                        try:
                            return format_str.format(*match.groups())
                        except:
                            continue

        # Additional information extraction
        extra_info = []
        
        # Look for OS information
        os_patterns = [
            r'\(([^)]+?(?:Linux|Unix|BSD|Ubuntu|Debian|CentOS|Red Hat|Windows)[^)]*)\)',
            r'(?:Linux|Unix|BSD|Ubuntu|Debian|CentOS|Red Hat|Windows)[/\s-][\w.]+'
        ]
        
        for pattern in os_patterns:
            os_match = re.search(pattern, banner, re.IGNORECASE)
            if os_match:
                extra_info.append(os_match.group(1))
                break

        # Look for additional components
        if 'PHP' in banner:
            php_match = re.search(r'PHP/(\d+\.\d+\.\d+)', banner)
            if php_match:
                extra_info.append(f"PHP/{php_match.group(1)}")
        
        if 'OpenSSL' in banner:
            ssl_match = re.search(r'OpenSSL/(\d+\.\d+\.\d+\w*)', banner)
            if ssl_match:
                extra_info.append(f"OpenSSL/{ssl_match.group(1)}")

        # Combine all information
        if extra_info:
            return f"{service} " + " ".join(extra_info)

        return service

    def scan_ports(self) -> None:
        """Scan ports using thread pool."""
        print(f"Scanning {len(self.ports)} ports on {self.target}")
        start_time = time.time()
        
        # Pre-resolve target IP
        target_ip = socket.gethostbyname(self.target)
        
        if self.aggressive:
            optimal_threads = min(2000, os.cpu_count() * 16)
            chunk_size = 5000
            original_timing = self.timing
            self.timing = 'insane'
        else:
            optimal_threads = min(100, os.cpu_count() * 2)
            chunk_size = 50
            original_timing = self.timing
            self.timing = 'sneaky'
        
        self.threads = max(self.threads, optimal_threads)
        
        # Initialize progress bar
        progress = ProgressBar(len(self.ports), prefix='Scanning:')
        ports_scanned = 0
        
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                if self.scan_type == 'tcp':
                    scan_fn = partial(self.tcp_connect_scan, target_ip=target_ip)
                    
                    if self.aggressive:
                        futures = [executor.submit(scan_fn, port) for port in self.ports]
                        for _ in as_completed(futures):
                            ports_scanned += 1
                            progress.update(ports_scanned)
                    else:
                        port_chunks = [self.ports[i:i + chunk_size] 
                                     for i in range(0, len(self.ports), chunk_size)]
                        for chunk in port_chunks:
                            futures = [executor.submit(scan_fn, port) for port in chunk]
                            for _ in as_completed(futures):
                                ports_scanned += 1
                                progress.update(ports_scanned)
                            if not self.aggressive:
                                time.sleep(random.uniform(0.5, 1.5))

        except KeyboardInterrupt:
            print("\nScan interrupted by user. Showing partial results.\n")
        finally:
            self.timing = original_timing
        
        scan_time = time.time() - start_time
        self._print_results(scan_time)

    def _print_results(self, scan_time: float) -> None:
        """Print scan results with banner information."""
        open_ports = {port: data for port, data in self.results.items() 
                     if data.get('state') == 'open'}
        
        if self.output_format == 'txt':
            print("\nScanning completed in {:.2f} seconds".format(scan_time))
            print(f"Found {len(open_ports)} open ports on {self.target}\n")
            
            if open_ports:
                # Nmap-like header
                print("PORT      STATE    SERVICE    VERSION")
                print("----------------------------------------------------")
                for port, data in sorted(open_ports.items()):
                    # Format port with protocol
                    port_str = f"{port}/tcp"
                    # Get service and version info
                    service = data['service']
                    version = data.get('banner', '')
                    
                    # Format the line like Nmap
                    print(f"{port_str:<9} {data['state']:<8} {service:<10} {version}")
            print()
        
        elif self.output_format == 'json':
            # JSON output format
            output = {
                'scan_info': {
                    'target': self.target,
                    'scan_time': scan_time,
                    'ports_scanned': len(self.ports),
                    'open_ports': len(open_ports)
                },
                'ports': self.results
            }
            print(json.dumps(output, indent=2))
        
        elif self.output_format == 'xml':
            # XML output format
            xml_output = [
                '<?xml version="1.0" encoding="UTF-8"?>',
                '<scan>',
                f'  <scaninfo target="{self.target}" time="{scan_time:.2f}" ports_scanned="{len(self.ports)}" open_ports="{len(open_ports)}"/>',
                '  <ports>'
            ]
            
            for port, data in sorted(open_ports.items()):
                xml_output.extend([
                    '    <port>',
                    f'      <number>{port}</number>',
                    f'      <state>{data["state"]}</state>',
                    f'      <service>{data["service"]}</service>',
                    f'      <banner>{data.get("banner", "")}</banner>',
                    '    </port>'
                ])
            
            xml_output.extend([
                '  </ports>',
                '</scan>'
            ])
            
            print('\n'.join(xml_output))

    def run(self) -> None:
        """Main execution method."""
        self.parse_arguments()
        self.validate_target()
        
        print(f"\nStarting EMAP scan on {self.target}")
        print(f"Scan type: {self.scan_type}")
        print(f"Port range: {min(self.ports)}-{max(self.ports)}")
        
        if not self.no_ping:
            if not self._check_host_up():
                print(f"\nHost {self.target} appears to be down.")
                return
        
        self.scan_ports()

    def _check_host_up(self) -> bool:
        """Check if host is up using a ping-like TCP connection."""
        try:
            socket.create_connection((self.target, 80), timeout=2)
            return True
        except (socket.timeout, socket.error):
            try:
                socket.create_connection((self.target, 443), timeout=2)
                return True
            except (socket.timeout, socket.error):
                return False

    def _advanced_service_probe(self, target_ip: str, port: int, service: str) -> str:
        """Advanced service probing with NSE-like functionality."""
        advanced_probes = {
            'HTTP': [
                # Multiple probes to identify web servers and technologies
                {
                    'send': (
                        b"GET / HTTP/1.1\r\n"
                        b"Host: {}\r\n"
                        b"User-Agent: Mozilla/5.0 (compatible; EMAP)\r\n"
                        b"Accept: */*\r\n"
                        b"Connection: close\r\n\r\n"
                    ),
                    'patterns': [
                        (r'Server: ([^\r\n]+)', '{0}'),
                        (r'X-Powered-By: ([^\r\n]+)', '{0}'),
                    ]
                },
                # Try HEAD request
                {
                    'send': (
                        b"HEAD / HTTP/1.1\r\n"
                        b"Host: {}\r\n"
                        b"User-Agent: Mozilla/5.0 (compatible; EMAP)\r\n"
                        b"Accept: */*\r\n\r\n"
                    ),
                    'patterns': [
                        (r'Server: ([^\r\n]+)', '{0}')
                    ]
                },
                # Try malformed request to trigger error pages
                {
                    'send': b"INVALID-REQUEST / HTTP/1.1\r\n\r\n",
                    'patterns': [
                        (r'<title>([^<]+)</title>', '{0}'),
                        (r'<h1>([^<]+)</h1>', '{0}')
                    ]
                }
            ],
            'FTP': [
                # Standard FTP probes
                {
                    'send': b"",  # Initial connection
                    'patterns': [(r'220[- ]([^\r\n]+)', '{0}')]
                },
                # SYST command
                {
                    'send': b"SYST\r\n",
                    'patterns': [(r'215[- ]([^\r\n]+)', 'System: {0}')]
                },
                # HELP command
                {
                    'send': b"HELP\r\n",
                    'patterns': [(r'214[- ]([^\r\n]+)', '{0}')]
                },
                # Try malformed command
                {
                    'send': b"INVALID\r\n",
                    'patterns': [(r'500[- ]([^\r\n]+)', '{0}')]
                }
            ],
            'SMTP': [
                # EHLO probe
                {
                    'send': b"EHLO emap.scanner\r\n",
                    'patterns': [
                        (r'220[- ]([^\r\n]+)', '{0}'),
                        (r'250[- ]([^\r\n]+)', '{0}')
                    ]
                },
                # HELP command
                {
                    'send': b"HELP\r\n",
                    'patterns': [(r'214[- ]([^\r\n]+)', '{0}')]
                },
                # Try malformed command
                {
                    'send': b"INVALID\r\n",
                    'patterns': [(r'500[- ]([^\r\n]+)', '{0}')]
                }
            ],
            'SSH': [
                # Initial probe
                {
                    'send': b"SSH-2.0-EMAP_Scanner\r\n",
                    'patterns': [(r'SSH-2\.0-([^\r\n]+)', '{0}')]
                },
                # Try invalid version
                {
                    'send': b"SSH-1.0-INVALID\r\n",
                    'patterns': [(r'Protocol mismatch', 'OpenSSH')]
                }
            ]
        }

        responses = []
        
        try:
            for probe in advanced_probes.get(service, []):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(2)
                        sock.connect((target_ip, port))
                        
                        # Handle SSL for HTTPS
                        if port == 443:
                            import ssl
                            context = ssl.create_default_context()
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            sock = context.wrap_socket(sock)
                        
                        # Send probe
                        if probe['send']:
                            if b'{}' in probe['send']:
                                sock.send(probe['send'].format(self.target).encode())
                            else:
                                sock.send(probe['send'])
                        
                        # Multiple reads to get full response
                        response = b""
                        while True:
                            try:
                                chunk = sock.recv(4096)
                                if not chunk:
                                    break
                                response += chunk
                            except socket.timeout:
                                break
                        
                        if response:
                            responses.append(response.decode('utf-8', errors='ignore'))
                
                except:
                    continue
        
        except Exception as e:
            if self.verbose:
                print(f"\nError in advanced probing for port {port}: {e}")
        
        # Process all responses
        if responses:
            combined_response = '\n'.join(responses)
            return self._identify_service_version(service, combined_response)
        
        return ""

    def _error_based_probe(self, target_ip: str, port: int, service: str) -> str:
        """Probe services using malformed requests to trigger revealing error messages."""
        error_probes = {
            'HTTP': [
                # Malformed HTTP requests
                {
                    'send': b"INVALID / HTTP/1.1\r\n\r\n",
                    'patterns': [
                        (r'<title>([^<]+)(Apache|nginx|IIS)[^<]+</title>', '{0}'),
                        (r'<h1>([^<]+)(Apache|nginx|IIS)[^<]+</h1>', '{0}'),
                        (r'Server: ([^\r\n]+)', '{0}')
                    ]
                },
                # HTTP 1.0 request (some servers reveal more in errors)
                {
                    'send': b"GET / HTTP/1.0\r\n\r\n",
                    'patterns': [
                        (r'Server: ([^\r\n]+)', '{0}')
                    ]
                }
            ],
            'MySQL': [
                # Invalid MySQL handshake
                {
                    'send': b"\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                    'patterns': [
                        (r'([0-9]+\.[0-9]+\.[0-9]+)-([^\r\n]+)', 'MySQL {0} {1}'),
                        (r'mysql_native_password', 'MySQL')
                    ]
                }
            ],
            'PostgreSQL': [
                # Invalid PostgreSQL startup packet
                {
                    'send': b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
                    'patterns': [
                        (r'PostgreSQL\s+([0-9.]+)', 'PostgreSQL {0}'),
                        (r'FATAL:[^\n]+', '{0}')
                    ]
                }
            ],
            'SMTP': [
                # Invalid SMTP commands
                {
                    'send': b"INVALIDCMD\r\n",
                    'patterns': [
                        (r'5\d\d[- ]([^\r\n]+)', '{0}'),
                        (r'(Postfix|Exim|Sendmail)[/\s-]([0-9][^\r\n]*)', '{0} {1}')
                    ]
                }
            ],
            'FTP': [
                # Invalid FTP commands
                {
                    'send': b"INVALID\r\n",
                    'patterns': [
                        (r'500[- ]([^\r\n]+)', '{0}'),
                        (r'(vsFTPd|ProFTPD|FileZilla)[/\s-]([0-9][^\r\n]*)', '{0} {1}')
                    ]
                }
            ],
            'SSH': [
                # Invalid SSH version
                {
                    'send': b"SSH-1.0-INVALID\r\n",
                    'patterns': [
                        (r'Protocol mismatch', 'OpenSSH'),
                        (r'Bad protocol version', 'SSH Server')
                    ]
                }
            ]
        }

        try:
            if service in error_probes:
                for probe in error_probes[service]:
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                            sock.settimeout(2)
                            sock.connect((target_ip, port))
                            
                            # Handle SSL for HTTPS
                            if port == 443:
                                import ssl
                                context = ssl.create_default_context()
                                context.check_hostname = False
                                context.verify_mode = ssl.CERT_NONE
                                sock = context.wrap_socket(sock)
                            
                            # Send malformed request
                            sock.send(probe['send'])
                            
                            # Get error response
                            response = b""
                            try:
                                while True:
                                    chunk = sock.recv(4096)
                                    if not chunk:
                                        break
                                    response += chunk
                            except socket.timeout:
                                pass
                            
                            if response:
                                error_text = response.decode('utf-8', errors='ignore')
                                # Try to match error patterns
                                for pattern, format_str in probe['patterns']:
                                    match = re.search(pattern, error_text, re.IGNORECASE)
                                    if match:
                                        groups = match.groups()
                                        return format_str.format(*groups)
                    except:
                        continue
        except:
            pass
        
        return ""

class ProgressBar:
    def __init__(self, total, prefix='Progress:', length=50):
        self.total = total
        self.prefix = prefix
        self.length = length
        self.current = 0
        self.start_time = time.time()
        
    def update(self, current):
        self.current = current
        filled = int(self.length * current // self.total)
        percentage = 100.0 * current / self.total
        
        # Choose color based on completion percentage
        if percentage < 30:
            color = Fore.RED
        elif percentage < 50:
            color = Fore.YELLOW
        elif percentage < 65:
            color = Fore.YELLOW
        else:
            color = Fore.GREEN
            
        bar = f"{color}█{Style.RESET_ALL}" * filled + '-' * (self.length - filled)
        percent = f"{color}{percentage:.1f}%{Style.RESET_ALL}"
        elapsed = time.time() - self.start_time
        rate = current / elapsed if elapsed > 0 else 0
        
        print(f'\r{self.prefix} |{bar}| {percent} ({rate:.0f} ports/sec)', end='')
        if current == self.total:
            print()

def main():
    scanner = EMAP()
    scanner.run()

if __name__ == "__main__":
    main() 