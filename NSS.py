#!/usr/bin/env python3
"""
Network Security Scanner
A tool for scanning networks and identifying potential security vulnerabilities
Author: Eduardo Muniz-Vega
Date: January 2026
"""

import nmap
import socket
from datetime import datetime
from colorama import Fore, Style, init
from tabulate import tabulate

# Initialize colorama for colored terminal output
init(autoreset=True)

class NetworkScanner:
    def __init__(self, target):
        """
        Initialize the scanner with a target IP or hostname
        
        Args:
            target (str): IP address or hostname to scan
        """
        self.target = target
        self.scanner = nmap.PortScanner()
        self.results = []
        
    def validate_target(self):
        """
        Validate that the target is reachable
        
        Returns:
            bool: True if target is valid, False otherwise
        """
        try:
            socket.gethostbyname(self.target)
            return True
        except socket.gaierror:
            print(f"{Fore.RED}[!] Error: Cannot resolve hostname {self.target}")
            return False
    
    def scan_ports(self, port_range="1-1000"):
        """
        Scan ports on the target system
        
        Args:
            port_range (str): Range of ports to scan (e.g., "1-1000" or "80,443,22")
        """
        print(f"{Fore.CYAN}[*] Starting port scan on {self.target}")
        print(f"{Fore.CYAN}[*] Scanning ports: {port_range}")
        print(f"{Fore.CYAN}[*] Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        try:
            # Perform the scan
            # -Pn: skip host
            # -sV: Service version detection
            # -T4: Timing template (faster)
            # -sT: TCP Connect Scan
            self.scanner.scan(self.target, port_range, arguments='-Pn -sT -T4')
            
            # Check if host is up
            if len(self.scanner.all_hosts()) == 0:
                print(f"{Fore.RED}[!] Host appears to be down or blocking pings")
                return
           
            # Process results
            for host in self.scanner.all_hosts():
                print(f"{Fore.GREEN}[+] Host: {host} is UP")
                print(f"{Fore.GREEN}[+] State: {self.scanner[host].state()}\n")
                
                # Get all protocols (tcp, udp, etc.)
                for proto in self.scanner[host].all_protocols():
                    print(f"{Fore.YELLOW}Protocol: {proto}")
                    
                    # Get all ports for this protocol
                    ports = self.scanner[host][proto].keys()
                    
                    for port in sorted(ports):
                        port_info = self.scanner[host][proto][port]
                        state = port_info['state']
                        service = port_info['name']
                        version = port_info.get('version', 'N/A')
                        product = port_info.get('product', 'N/A')
                        packet = port_info.get('reason', 'N/A')
                        
                        # Store results
                        self.results.append({
                            'Port': port,
                            'State': state,
                            'Service': service,
                            'Version': f"{product} {version}".strip(),
                            'Packet':f"{packet}".strip()
                        })
                        
                        # Color code based on state
                        if state == 'open':
                            color = Fore.GREEN
                        elif state == 'filtered':
                            color = Fore.YELLOW
                        else:
                            color = Fore.RED
                        
                        print(f"{color}  Port {port}: {state} - {service} ({product} {version} {packet})")
        
        except nmap.PortScannerError as e:
            print(f"{Fore.RED}[!] Nmap error: {e}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error during scan: {e}")

        return self.results
    
    def check_common_vulnerabilities(self):
        """
        Check for common security issues based on open ports
        This is a basic check - you'll expand this!
        """
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}[*] Checking for Common Vulnerabilities")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        vulnerabilities = []
        
        for result in self.results:
            port = result['Port']
            service = result['Service']
            
            # TODO: Add more vulnerability checks here
            # This is where YOU will add detection logic!
            
            # Example checks:
            if port == 23 and result['State'] == 'open':
                vulnerabilities.append({
                    'Port': port,
                    'Issue': 'Telnet is insecure (unencrypted)',
                    'Severity': 'HIGH',
                    'Recommendation': 'Use SSH (port 22) instead'
                })
            
            if port == 21 and result['State'] == 'open':
                vulnerabilities.append({
                    'Port': port,
                    'Issue': 'FTP detected (often unencrypted)',
                    'Severity': 'MEDIUM',
                    'Recommendation': 'Use SFTP or FTPS instead'
                })
            
            if port == 3389 and result['State'] == 'open':
                vulnerabilities.append({
                    'Port': port,
                    'Issue': 'RDP exposed to network',
                    'Severity': 'MEDIUM',
                    'Recommendation': 'Restrict access or use VPN'
                })
            if port == 445 and result['State'] == 'open':
                vulnerabilities.append({
                    'Port': port,
                    'Issue': 'Personal files and info are seen',
                    'Severity': 'MEDIUM',
                    'Recommendation': 'Check for accessible shares'
                })
            if port == 80 and result['State'] == 'open':
                vulnerabilities.append({
                    'Port': port,
                    'Issue': 'Personal files and info are seen',
                    'Severity': 'MEDIUM',
                    'Recommendation': 'Search up the website, and see if there is contenct wring in it(error messages, etc.)'
                })
            if port == 1433 and result['State'] == 'open':
                vulnerabilities.append({
                    'Port': port,
                    'Issue': 'MSSQL data leaked',
                    'Severity': 'HIGH',
                    'Recommendation': 'Using terminal check what data got leaked'
                })
            if port == 3389 and result['State'] == 'open':
                vulnerabilities.append({
                    'Port': port,
                    'Issue': 'Someone is looking or taking control of your desktop',
                    'Severity': 'HIGH',
                    'Recommendation': 'Use a VPN and block port 3389 in order to block future and current RDP connections'
                })
        
        if vulnerabilities:
            print(f"{Fore.RED}[!] Found {len(vulnerabilities)} potential security issues:\n")
            for vuln in vulnerabilities:
                severity_color = Fore.RED if vuln['Severity'] == 'HIGH' else Fore.YELLOW
                print(f"{severity_color}[{vuln['Severity']}] Port {vuln['Port']}: {vuln['Issue']}")
                print(f"{Fore.CYAN}    Recommendation: {vuln['Recommendation']}\n")
        else:
            print(f"{Fore.GREEN}[+] No common vulnerabilities detected in this scan")
        return vulnerabilities
    
    def generate_report(self):
        """
        Generate a formatted report of scan results
        """
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}SCAN REPORT - {self.target}")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        if self.results:
            print(tabulate(self.results, headers='keys', tablefmt='grid'))
        else:
            print(f"{Fore.YELLOW}[!] No open ports found")
        
        print(f"\n{Fore.CYAN}Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}Total ports scanned: Check nmap output above")
        print(f"{Fore.GREEN}Total open ports: {len(self.results)}\n")

        return self.results

def main():
    """
    Main function to run the scanner
    """
    print(f"{Fore.CYAN}")
    print("="*60)
    print("        NETWORK SECURITY SCANNER v1.0")
    print("="*60)
    print(f"{Style.RESET_ALL}")
    
    # Get target from user
    target = input(f"{Fore.YELLOW}Enter target IP or hostname: {Style.RESET_ALL}")
    
    # Get port range
    print(f"\n{Fore.YELLOW}Port range options:")
    print("  1. Quick scan (top 100 ports)")
    print("  2. Standard scan (ports 1-1000)")
    print("  3. Full scan (ports 1-65535) - SLOW!")
    print("  4. Custom range")
    
    choice = input(f"{Fore.YELLOW}Choose option (1-4): {Style.RESET_ALL}")
    
    if choice == '1':
        port_range = "1-100"
    elif choice == '2':
        port_range = "1-1000"
    elif choice == '3':
        port_range = "1-65535"
    elif choice == '4':
        port_range = input(f"{Fore.YELLOW}Enter port range (e.g., 1-1000 or 80,443,22): {Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Invalid choice, using standard scan")
        port_range = "1-1000"
    
    # Create scanner instance
    scanner = NetworkScanner(target)
    
    # Validate target
    if not scanner.validate_target():
        return
    
    # Perform scan
    scanner.scan_ports(port_range)
    
    # Check for vulnerabilities
    scanner.check_common_vulnerabilities()
    
    # Generate report
    scanner.generate_report()
    
     
    save = input(f"\n{Fore.YELLOW}Save report to file? (y/n): {Style.RESET_ALL}")
    if save.lower() == 'y':
        results = scanner.generate_report()  # Now this returns data
    
        with open("results.txt", "w") as f: 
            f.write("===== Network Scan Results =====\n\n")
        
            for result in results:
                f.write(f"Port: {result['Port']}\n")
                f.write(f"  State: {result['State']}\n")
                f.write(f"  Service: {result['Service']}\n")
                f.write(f"  Version: {result['Version']}\n")
                f.write(f"  Reason: {result['Packet']}\n\n")
        
            f.write(f"Total open ports: {len(results)}\n")
    elif save.lower() == 'n': 
        return
    print(f"{Fore.GREEN}[+] Results saved to results.txt") 

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user")
    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected error: {e}")