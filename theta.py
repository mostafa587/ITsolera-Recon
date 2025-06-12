#!/usr/bin/env python3
"""
Professional Reconnaissance Tool for Cybersecurity Assessment
A comprehensive tool combining active and passive reconnaissance techniques
Designed for authorized security testing and educational presentations
"""

import argparse
import os
import sys
import subprocess
import requests
import socket
import dns.resolver
import whois
import json
import re
import time
from urllib.parse import urlparse
from datetime import datetime
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('recon_tool.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SecurityReconTool:
    """Main class for the combined reconnaissance tool"""
    
    def __init__(self, target):
        self.target = target.lower().strip()
        self.script_dir = os.getcwd()
        self.results_path = os.path.join(self.script_dir, "ReconResults")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.results = {}
        self.subdomains = set()
        
        # Initialize results directory
        self.setup_directories()
    
    def setup_directories(self):
        """Create necessary directories for results"""
        if not os.path.exists(self.results_path):
            os.makedirs(self.results_path)
            logger.info(f"Created results directory: {self.results_path}")
    
    def banner(self):
        """Display tool banner"""
        print("""
╔═══════════════════════════════════════════════════════════════╗
║              PROFESSIONAL RECONNAISSANCE TOOL                 ║
║                For Cybersecurity Assessment                   ║
║                  Council Presentation Demo                    ║
╚═══════════════════════════════════════════════════════════════╝
        """)
        print(f"Target: {self.target}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)
    
    def validate_domain(self, domain):
        """Validate domain format"""
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, domain)) and len(domain) <= 253
    
    def dns_enumeration(self):
        """Comprehensive DNS enumeration"""
        print(f"\n[+] Starting DNS Enumeration for {self.target}")
        dns_info = {}
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                dns_info[record_type] = [str(rdata) for rdata in answers]
                print(f"  {record_type}: {dns_info[record_type]}")
                logger.info(f"DNS {record_type} records found: {len(dns_info[record_type])}")
            except Exception as e:
                dns_info[record_type] = f"No {record_type} records found"
                logger.debug(f"No {record_type} records for {self.target}: {e}")
        
        self.results['dns_enumeration'] = dns_info
        return dns_info
    
    def whois_lookup(self):
        """WHOIS information gathering"""
        print(f"\n[+] Performing WHOIS lookup for {self.target}")
        try:
            w = whois.whois(self.target)
            whois_info = {
                'domain_name': str(w.domain_name) if w.domain_name else None,
                'registrar': str(w.registrar) if w.registrar else None,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'name_servers': w.name_servers if w.name_servers else None,
                'emails': w.emails if w.emails else None,
                'organization': str(w.org) if hasattr(w, 'org') and w.org else None,
                'country': str(w.country) if hasattr(w, 'country') and w.country else None
            }
            
            for key, value in whois_info.items():
                if value and str(value) != 'None':
                    print(f"  {key.replace('_', ' ').title()}: {value}")
            
            self.results['whois_lookup'] = whois_info
            logger.info("WHOIS lookup completed successfully")
            return whois_info
        except Exception as e:
            print(f"  WHOIS lookup failed: {e}")
            logger.error(f"WHOIS lookup failed: {e}")
            self.results['whois_lookup'] = {'error': str(e)}
            return None
    
    def passive_subdomain_enumeration(self):
        """Passive subdomain enumeration using multiple sources"""
        print(f"\n[+] Starting Passive Subdomain Enumeration for {self.target}")
        
        # Certificate Transparency (crt.sh)
        self.crt_sh_enumeration()
        time.sleep(1)
        
        # ThreatCrowd API
        self.threatcrowd_enumeration()
        time.sleep(1)
        
        # HackerTarget API
        self.hackertarget_enumeration()
        time.sleep(1)
        
        # Wordlist enumeration
        self.wordlist_enumeration()
        
        # Verify live subdomains
        live_subdomains = self.verify_live_subdomains()
        
        print(f"\n  [+] Total subdomains found: {len(self.subdomains)}")
        print(f"  [+] Live subdomains: {len(live_subdomains)}")
        
        subdomain_results = {
            'total_found': len(self.subdomains),
            'all_subdomains': sorted(list(self.subdomains)),
            'live_subdomains': sorted(live_subdomains),
            'live_count': len(live_subdomains)
        }
        
        self.results['subdomain_enumeration'] = subdomain_results
        return subdomain_results
    
    def crt_sh_enumeration(self):
        """Certificate Transparency enumeration"""
        try:
            print("  [*] Querying Certificate Transparency logs...")
            url = f"https://crt.sh/?q=%25.{self.target}&output=json"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                certificates = response.json()
                count = 0
                for cert in certificates:
                    name_value = cert.get('name_value', '')
                    if name_value:
                        names = name_value.split('\n')
                        for name in names:
                            name = name.strip().lower()
                            if name.endswith(f".{self.target}") and '*' not in name:
                                self.subdomains.add(name)
                                count += 1
                print(f"    Found {count} subdomains from CT logs")
                logger.info(f"Certificate Transparency: {count} subdomains found")
        except Exception as e:
            print(f"    Certificate Transparency query failed: {e}")
            logger.error(f"CT enumeration failed: {e}")
    
    def threatcrowd_enumeration(self):
        """ThreatCrowd API enumeration"""
        try:
            print("  [*] Querying ThreatCrowd API...")
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.target}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = data.get('subdomains', [])
                count = 0
                for subdomain in subdomains:
                    if subdomain and subdomain.endswith(f".{self.target}"):
                        self.subdomains.add(subdomain.lower())
                        count += 1
                print(f"    Found {count} subdomains from ThreatCrowd")
                logger.info(f"ThreatCrowd: {count} subdomains found")
        except Exception as e:
            print(f"    ThreatCrowd query failed: {e}")
            logger.error(f"ThreatCrowd enumeration failed: {e}")
    
    def hackertarget_enumeration(self):
        """HackerTarget API enumeration"""
        try:
            print("  [*] Querying HackerTarget API...")
            url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                count = 0
                for line in lines:
                    if ',' in line and not line.startswith('error'):
                        subdomain = line.split(',')[0].strip().lower()
                        if subdomain.endswith(f".{self.target}") and subdomain != self.target:
                            self.subdomains.add(subdomain)
                            count += 1
                print(f"    Found {count} subdomains from HackerTarget")
                logger.info(f"HackerTarget: {count} subdomains found")
        except Exception as e:
            print(f"    HackerTarget query failed: {e}")
            logger.error(f"HackerTarget enumeration failed: {e}")
    
    def wordlist_enumeration(self):
        """Wordlist-based subdomain enumeration"""
        print("  [*] Performing wordlist enumeration...")
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'blog', 'shop', 'secure', 'vpn', 'remote', 'support', 'help',
            'forum', 'portal', 'login', 'dashboard', 'cpanel', 'webmail',
            'mobile', 'app', 'cdn', 'static', 'assets', 'beta', 'demo',
            'smtp', 'pop', 'imap', 'ns1', 'ns2', 'mx', 'mx1', 'mx2'
        ]
        
        def check_subdomain(sub):
            subdomain = f"{sub}.{self.target}"
            try:
                socket.gethostbyname(subdomain)
                return subdomain
            except:
                return None
        
        found_count = 0
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_sub = {executor.submit(check_subdomain, sub): sub for sub in common_subs}
            for future in as_completed(future_to_sub):
                result = future.result()
                if result:
                    self.subdomains.add(result.lower())
                    found_count += 1
        
        print(f"    Found {found_count} subdomains from wordlist")
        logger.info(f"Wordlist enumeration: {found_count} subdomains found")
    
    def verify_live_subdomains(self):
        """Verify which subdomains are live"""
        print("  [*] Verifying live subdomains...")
        live_subdomains = []
        
        def check_live(subdomain):
            try:
                socket.gethostbyname(subdomain)
                return subdomain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_subdomain = {executor.submit(check_live, sub): sub for sub in self.subdomains}
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    live_subdomains.append(result)
        
        return live_subdomains
    
    def web_technology_detection(self):
        """Detect web technologies and security headers"""
        print(f"\n[+] Detecting web technologies for {self.target}")
        tech_info = {}
        
        protocols = ['https', 'http']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{self.target}"
                response = self.session.get(url, timeout=10, allow_redirects=True, verify=False)
                headers = response.headers
                content = response.text[:5000]  # First 5KB for analysis
                
                # Basic information
                tech_info[f'{protocol}_status'] = response.status_code
                tech_info[f'{protocol}_server'] = headers.get('Server', 'Not disclosed')
                tech_info[f'{protocol}_powered_by'] = headers.get('X-Powered-By', 'Not disclosed')
                
                # Security headers analysis
                security_headers = {
                    'X-Frame-Options': headers.get('X-Frame-Options'),
                    'X-XSS-Protection': headers.get('X-XSS-Protection'),
                    'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                    'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                    'Content-Security-Policy': headers.get('Content-Security-Policy'),
                    'Referrer-Policy': headers.get('Referrer-Policy')
                }
                
                present_headers = {k: v for k, v in security_headers.items() if v}
                missing_headers = [k for k, v in security_headers.items() if not v]
                
                tech_info[f'{protocol}_security_headers_present'] = present_headers
                tech_info[f'{protocol}_security_headers_missing'] = missing_headers
                
                # Technology detection
                tech_patterns = {
                    'WordPress': r'wp-content|wp-includes|wordpress|wp-json',
                    'Joomla': r'joomla|com_content|option=com_',
                    'Drupal': r'drupal|sites/default|sites/all',
                    'PHP': r'\.php|PHPSESSID',
                    'ASP.NET': r'asp\.net|__viewstate|aspx',
                    'jQuery': r'jquery',
                    'Bootstrap': r'bootstrap',
                    'React': r'react|_react',
                    'Angular': r'angular|ng-',
                    'Apache': r'apache',
                    'Nginx': r'nginx',
                    'IIS': r'iis|microsoft-iis'
                }
                
                detected_tech = []
                for tech, pattern in tech_patterns.items():
                    if re.search(pattern, content + str(headers), re.IGNORECASE):
                        detected_tech.append(tech)
                
                tech_info[f'{protocol}_detected_technologies'] = detected_tech
                
                print(f"  {protocol.upper()}:")
                print(f"    Status: {tech_info[f'{protocol}_status']}")
                print(f"    Server: {tech_info[f'{protocol}_server']}")
                print(f"    Technologies: {detected_tech}")
                print(f"    Security Headers Present: {len(present_headers)}/6")
                print(f"    Security Headers Missing: {missing_headers}")
                
                break  # If one protocol works, use it
                
            except Exception as e:
                tech_info[f'{protocol}_error'] = str(e)
                logger.error(f"Web technology detection failed for {protocol}: {e}")
                continue
        
        self.results['web_technology'] = tech_info
        return tech_info
    
    def run_external_tools(self):
        """Run external tools if available (Sublist3r, httpx, etc.)"""
        print(f"\n[+] Running External Tools (if available)")
        external_results = {}
        
        # Try to run Sublist3r
        try:
            sublist3r_output = os.path.join(self.results_path, "sublist3r_output.txt")
            print("  [*] Attempting to run Sublist3r...")
            
            # Try direct execution first
            try:
                result = subprocess.run(
                    ["sublist3r", "-d", self.target, "-o", sublist3r_output],
                    capture_output=True, text=True, timeout=300
                )
                if result.returncode == 0:
                    print("    Sublist3r completed successfully")
                    external_results['sublist3r'] = 'success'
                    logger.info("Sublist3r executed successfully")
                else:
                    print(f"    Sublist3r failed: {result.stderr}")
                    external_results['sublist3r'] = 'failed'
            except FileNotFoundError:
                print("    Sublist3r not found in PATH")
                external_results['sublist3r'] = 'not_found'
            except subprocess.TimeoutExpired:
                print("    Sublist3r timed out")
                external_results['sublist3r'] = 'timeout'
                
        except Exception as e:
            print(f"    Sublist3r error: {e}")
            external_results['sublist3r'] = f'error: {e}'
        
        # Try to run httpx for live subdomain verification
        if self.subdomains:
            try:
                httpx_output = os.path.join(self.results_path, "httpx_output.txt")
                subdomain_file = os.path.join(self.results_path, "temp_subdomains.txt")
                
                # Write subdomains to temporary file
                with open(subdomain_file, 'w') as f:
                    for subdomain in self.subdomains:
                        f.write(f"{subdomain}\n")
                
                print("  [*] Attempting to run httpx...")
                result = subprocess.run(
                    ["httpx", "-l", subdomain_file, "-o", httpx_output, "-silent"],
                    capture_output=True, text=True, timeout=300
                )
                
                if result.returncode == 0:
                    print("    httpx completed successfully")
                    external_results['httpx'] = 'success'
                    logger.info("httpx executed successfully")
                else:
                    external_results['httpx'] = 'failed'
                    
            except FileNotFoundError:
                print("    httpx not found in PATH")
                external_results['httpx'] = 'not_found'
            except Exception as e:
                print(f"    httpx error: {e}")
                external_results['httpx'] = f'error: {e}'
        
        self.results['external_tools'] = external_results
        return external_results
    
    def generate_comprehensive_report(self):
        """Generate comprehensive reports for presentation"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # JSON Report
        json_filename = os.path.join(self.results_path, f"recon_report_{self.target}_{timestamp}.json")
        report_data = {
            'target': self.target,
            'scan_date': datetime.now().isoformat(),
            'tool_version': '2.0 - Combined Professional Tool',
            'results': self.results,
            'summary': {
                'modules_executed': list(self.results.keys()),
                'total_subdomains_found': len(self.results.get('subdomain_enumeration', {}).get('all_subdomains', [])),
                'live_subdomains_found': len(self.results.get('subdomain_enumeration', {}).get('live_subdomains', [])),
                'dns_records_found': len([k for k, v in self.results.get('dns_enumeration', {}).items() if isinstance(v, list)]),
                'technologies_detected': len(self.results.get('web_technology', {}).get('https_detected_technologies', []) + 
                                           self.results.get('web_technology', {}).get('http_detected_technologies', [])),
                'scan_successful': True
            }
        }
        
        with open(json_filename, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        # Executive Summary Report
        summary_filename = os.path.join(self.results_path, f"executive_summary_{self.target}_{timestamp}.txt")
        with open(summary_filename, 'w') as f:
            f.write("="*80 + "\n")
            f.write("CYBERSECURITY RECONNAISSANCE ASSESSMENT REPORT\n")
            f.write("="*80 + "\n")
            f.write(f"Target Domain: {self.target}\n")
            f.write(f"Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Tool Version: Professional Reconnaissance Tool v2.0\n")
            f.write("="*80 + "\n\n")
            
            # Executive Summary
            summary = report_data['summary']
            f.write("EXECUTIVE SUMMARY:\n")
            f.write("-" * 20 + "\n")
            f.write(f"• Assessment completed successfully for {self.target}\n")
            f.write(f"• Total subdomains discovered: {summary['total_subdomains_found']}\n")
            f.write(f"• Live subdomains identified: {summary['live_subdomains_found']}\n")
            f.write(f"• DNS records analyzed: {summary['dns_records_found']} types\n")
            f.write(f"• Web technologies detected: {summary['technologies_detected']}\n")
            f.write(f"• Assessment modules executed: {len(summary['modules_executed'])}\n\n")
            
            # Key Findings
            f.write("KEY FINDINGS:\n")
            f.write("-" * 15 + "\n")
            
            # Subdomain findings
            if 'subdomain_enumeration' in self.results:
                subdomains = self.results['subdomain_enumeration']
                f.write(f"1. SUBDOMAIN EXPOSURE:\n")
                f.write(f"   - {subdomains['total_found']} total subdomains discovered\n")
                f.write(f"   - {subdomains['live_count']} subdomains are currently accessible\n")
                if subdomains['live_subdomains']:
                    f.write("   - Live subdomains:\n")
                    for subdomain in subdomains['live_subdomains'][:10]:  # Top 10
                        f.write(f"     * {subdomain}\n")
                    if len(subdomains['live_subdomains']) > 10:
                        f.write(f"     * ... and {len(subdomains['live_subdomains']) - 10} more\n")
                f.write("\n")
            
            # Technology findings
            if 'web_technology' in self.results:
                tech = self.results['web_technology']
                f.write("2. WEB TECHNOLOGY STACK:\n")
                for protocol in ['https', 'http']:
                    if f'{protocol}_detected_technologies' in tech:
                        technologies = tech[f'{protocol}_detected_technologies']
                        if technologies:
                            f.write(f"   - {protocol.upper()} Technologies: {', '.join(technologies)}\n")
                    
                    # Security headers analysis
                    if f'{protocol}_security_headers_missing' in tech:
                        missing = tech[f'{protocol}_security_headers_missing']
                        if missing:
                            f.write(f"   - Missing Security Headers ({protocol.upper()}): {', '.join(missing)}\n")
                f.write("\n")
            
            # DNS findings
            if 'dns_enumeration' in self.results:
                dns = self.results['dns_enumeration']
                f.write("3. DNS CONFIGURATION:\n")
                for record_type, records in dns.items():
                    if isinstance(records, list) and records:
                        f.write(f"   - {record_type} Records: {len(records)} found\n")
                f.write("\n")
            
            # Recommendations
            f.write("SECURITY RECOMMENDATIONS:\n")
            f.write("-" * 25 + "\n")
            f.write("1. Review subdomain inventory and disable unused services\n")
            f.write("2. Implement proper security headers on all web applications\n")
            f.write("3. Ensure DNS records don't expose sensitive information\n")
            f.write("4. Regular security assessments and monitoring\n")
            f.write("5. Implement proper access controls and authentication\n\n")
            
            f.write("="*80 + "\n")
            f.write("End of Report\n")
            f.write("="*80 + "\n")
        
        # Console output
        print("\n" + "="*80)
        print("                    RECONNAISSANCE ASSESSMENT COMPLETED")
        print("="*80)
        print(f"Target: {self.target}")
        print(f"Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Subdomains: {report_data['summary']['total_subdomains_found']}")
        print(f"Live Subdomains: {report_data['summary']['live_subdomains_found']}")
        print(f"Modules Executed: {len(report_data['summary']['modules_executed'])}")
        print("="*80)
        print(f"\n[+] Detailed JSON report: {json_filename}")
        print(f"[+] Executive summary: {summary_filename}")
        print(f"[+] Logs available in: recon_tool.log")
        
        return report_data
    
    def run_full_assessment(self):
        """Run the complete reconnaissance assessment"""
        try:
            # Validate target
            if not self.validate_domain(self.target):
                print("[!] Invalid domain format")
                return False
            
            # Display banner
            self.banner()
            
            # Execute all modules
            print("\n[INFO] Starting comprehensive reconnaissance assessment...")
            logger.info(f"Starting assessment for {self.target}")
            
            # DNS Enumeration
            self.dns_enumeration()
            time.sleep(1)
            
            # WHOIS Lookup
            self.whois_lookup()
            time.sleep(1)
            
            # Subdomain Enumeration
            self.passive_subdomain_enumeration()
            time.sleep(1)
            
            # Web Technology Detection
            self.web_technology_detection()
            time.sleep(1)
            
            # External Tools (if available)
            self.run_external_tools()
            
            # Generate comprehensive report
            self.generate_comprehensive_report()
            
            logger.info("Assessment completed successfully")
            return True
            
        except KeyboardInterrupt:
            print("\n[!] Assessment interrupted by user")
            logger.warning("Assessment interrupted by user")
            return False
        except Exception as e:
            print(f"[!] Assessment failed: {e}")
            logger.error(f"Assessment failed: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(
        description='Professional Reconnaissance Tool for Cybersecurity Assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com                    # Full reconnaissance assessment
  %(prog)s --target example.com          # Alternative syntax
  
Note: This tool is designed for authorized security testing only.
      Ensure you have proper authorization before scanning any domain.
        """
    )
    
    parser.add_argument('target', nargs='?', help='Target domain (e.g., example.com)')
    parser.add_argument('-t', '--target', dest='target_flag', help='Target domain (alternative syntax)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Get target from either positional or flag argument
    target = args.target or args.target_flag
    
    if not target:
        print("[!] Please specify a target domain")
        parser.print_help()
        sys.exit(1)
    
    # Set verbose logging if requested
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize and run the tool
    try:
        recon_tool = SecurityReconTool(target)
        success = recon_tool.run_full_assessment()
        
        if success:
            print("\n[+] Assessment completed successfully!")
            print("[+] Review the generated reports for detailed findings")
            sys.exit(0)
        else:
            print("\n[!] Assessment completed with errors")
            sys.exit(1)
            
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
