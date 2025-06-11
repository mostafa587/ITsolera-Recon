#!/usr/bin/env python3
"""
Enhanced Passive Reconnaissance Tool
A comprehensive modular tool for ethical security testing and information gathering
Integrates external APIs for advanced subdomain enumeration
"""

import requests
import socket
import dns.resolver
import whois
import json
import re
import time
from urllib.parse import urlparse
import argparse
import sys
from datetime import datetime
import ssl
import base64
from urllib.parse import quote
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

class BaseReconModule:
    """Base class for all reconnaissance modules"""
    def __init__(self, target, session=None):
        self.target = target
        self.session = session or requests.Session()
        self.results = {}
    
    def execute(self):
        """Override this method in each module"""
        raise NotImplementedError

class DNSEnumerationModule(BaseReconModule):
    """DNS enumeration module"""
    
    def execute(self):
        print(f"\n[+] Starting DNS Enumeration for {self.target}")
        dns_info = {}
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                dns_info[record_type] = [str(rdata) for rdata in answers]
                print(f"  {record_type}: {dns_info[record_type]}")
            except Exception:
                dns_info[record_type] = f"No {record_type} records found"
        
        # Additional DNS information
        try:
            # Get authoritative nameservers
            ns_records = dns.resolver.resolve(self.target, 'NS')
            dns_info['authoritative_ns'] = [str(ns) for ns in ns_records]
        except Exception:
            pass
        
        self.results = dns_info
        return dns_info

class WHOISModule(BaseReconModule):
    """WHOIS lookup module"""
    
    def execute(self):
        print(f"\n[+] Performing WHOIS lookup for {self.target}")
        try:
            w = whois.whois(self.target)
            whois_info = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'name_servers': w.name_servers,
                'emails': w.emails,
                'organization': w.org,
                'country': w.country,
                'state': w.state,
                'city': w.city,
                'registrant_name': w.name,
                'admin_email': w.admin_email if hasattr(w, 'admin_email') else None,
                'tech_email': w.tech_email if hasattr(w, 'tech_email') else None
            }
            
            for key, value in whois_info.items():
                if value and value != 'None':
                    print(f"  {key.replace('_', ' ').title()}: {value}")
            
            self.results = whois_info
            return whois_info
        except Exception as e:
            print(f"  WHOIS lookup failed: {e}")
            self.results = {'error': str(e)}
            return None

class SubdomainEnumerationModule(BaseReconModule):
    """Advanced subdomain enumeration using multiple APIs and techniques"""
    
    def __init__(self, target, session=None):
        super().__init__(target, session)
        self.subdomains = set()
        self.timeout = 10
    
    def crt_sh_enumeration(self):
        """Enumerate subdomains using crt.sh"""
        try:
            print("  [*] Querying crt.sh...")
            url = f"https://crt.sh/?q=%25.{self.target}&output=json"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                certificates = response.json()
                for cert in certificates:
                    name_value = cert.get('name_value', '')
                    if name_value:
                        # Handle multiple names separated by newlines
                        names = name_value.split('\n')
                        for name in names:
                            name = name.strip().lower()
                            if name.endswith(f".{self.target}") and '*' not in name:
                                self.subdomains.add(name)
                                print(f"    Found: {name}")
        except Exception as e:
            print(f"    crt.sh query failed: {e}")
    
    def threatcrowd_enumeration(self):
        """Enumerate subdomains using ThreatCrowd API"""
        try:
            print("  [*] Querying ThreatCrowd...")
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.target}"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = data.get('subdomains', [])
                for subdomain in subdomains:
                    if subdomain and subdomain.endswith(f".{self.target}"):
                        self.subdomains.add(subdomain.lower())
                        print(f"    Found: {subdomain}")
        except Exception as e:
            print(f"    ThreatCrowd query failed: {e}")
    
    def hackertarget_enumeration(self):
        """Enumerate subdomains using HackerTarget API"""
        try:
            print("  [*] Querying HackerTarget...")
            url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                for line in lines:
                    if ',' in line:
                        subdomain = line.split(',')[0].strip().lower()
                        if subdomain.endswith(f".{self.target}") and subdomain != self.target:
                            self.subdomains.add(subdomain)
                            print(f"    Found: {subdomain}")
        except Exception as e:
            print(f"    HackerTarget query failed: {e}")
    
    def virustotal_enumeration(self):
        """Enumerate subdomains using VirusTotal API (requires API key)"""
        try:
            print("  [*] Querying VirusTotal...")
            # Note: This would require an API key in production
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {
                'apikey': 'YOUR_VT_API_KEY',  # Users need to add their own API key
                'domain': self.target
            }
            # Skip if no API key provided
            if params['apikey'] == 'YOUR_VT_API_KEY':
                print("    VirusTotal API key not configured")
                return
                
            response = self.session.get(url, params=params, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                subdomains = data.get('subdomains', [])
                for subdomain in subdomains:
                    full_subdomain = f"{subdomain}.{self.target}"
                    self.subdomains.add(full_subdomain.lower())
                    print(f"    Found: {full_subdomain}")
        except Exception as e:
            print(f"    VirusTotal query failed: {e}")
    
    def wordlist_enumeration(self):
        """Traditional wordlist-based enumeration"""
        print("  [*] Performing wordlist enumeration...")
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'blog', 'shop', 'secure', 'vpn', 'remote', 'support', 'help',
            'forum', 'portal', 'login', 'dashboard', 'cpanel', 'webmail',
            'm', 'mobile', 'app', 'apps', 'cdn', 'static', 'assets', 'img',
            'media', 'beta', 'demo', 'old', 'new', 'v1', 'v2', 'smtp',
            'pop', 'imap', 'ns1', 'ns2', 'mx', 'mx1', 'mx2', 'exchange'
        ]
        
        def check_subdomain(sub):
            subdomain = f"{sub}.{self.target}"
            try:
                socket.gethostbyname(subdomain)
                return subdomain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_sub = {executor.submit(check_subdomain, sub): sub for sub in common_subs}
            for future in as_completed(future_to_sub):
                result = future.result()
                if result:
                    self.subdomains.add(result.lower())
                    print(f"    Found: {result}")
    
    def execute(self):
        print(f"\n[+] Enumerating subdomains for {self.target}")
        
        # Run all enumeration methods
        self.crt_sh_enumeration()
        time.sleep(1)
        self.threatcrowd_enumeration()
        time.sleep(1)
        self.hackertarget_enumeration()
        time.sleep(1)
        self.virustotal_enumeration()
        time.sleep(1)
        self.wordlist_enumeration()
        
        # Verify live subdomains
        live_subdomains = []
        print("\n  [*] Verifying live subdomains...")
        
        for subdomain in self.subdomains:
            try:
                socket.gethostbyname(subdomain)
                live_subdomains.append(subdomain)
                print(f"    Live: {subdomain}")
            except:
                pass
        
        print(f"\n  [+] Found {len(self.subdomains)} total subdomains")
        print(f"  [+] {len(live_subdomains)} subdomains are live")
        
        self.results = {
            'total_found': len(self.subdomains),
            'all_subdomains': sorted(list(self.subdomains)),
            'live_subdomains': sorted(live_subdomains),
            'live_count': len(live_subdomains)
        }
        
        return self.results

class WebTechnologyModule(BaseReconModule):
    """Web technology detection module"""
    
    def execute(self):
        print(f"\n[+] Detecting web technologies for {self.target}")
        tech_info = {}
        
        protocols = ['http', 'https']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{self.target}"
                response = self.session.get(url, timeout=10, allow_redirects=True)
                headers = response.headers
                content = response.text
                
                # Basic information
                tech_info[f'{protocol}_status'] = response.status_code
                tech_info[f'{protocol}_server'] = headers.get('Server', 'Not disclosed')
                tech_info[f'{protocol}_powered_by'] = headers.get('X-Powered-By', 'Not disclosed')
                tech_info[f'{protocol}_content_type'] = headers.get('Content-Type', 'Not disclosed')
                
                # Security headers
                security_headers = {
                    'X-Frame-Options': headers.get('X-Frame-Options'),
                    'X-XSS-Protection': headers.get('X-XSS-Protection'),
                    'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                    'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                    'Content-Security-Policy': headers.get('Content-Security-Policy')
                }
                tech_info[f'{protocol}_security_headers'] = {k: v for k, v in security_headers.items() if v}
                
                # Technology detection patterns
                tech_patterns = {
                    'WordPress': r'wp-content|wp-includes|wordpress|wp-json',
                    'Joomla': r'joomla|com_content|option=com_',
                    'Drupal': r'drupal|sites/default|sites/all',
                    'PHP': r'\.php|php|PHPSESSID',
                    'ASP.NET': r'asp\.net|__viewstate|aspx',
                    'JSP': r'\.jsp|jsessionid',
                    'jQuery': r'jquery',
                    'Bootstrap': r'bootstrap',
                    'React': r'react|_react',
                    'Angular': r'angular|ng-',
                    'Vue.js': r'vue\.js|__vue',
                    'Laravel': r'laravel',
                    'Django': r'django|csrfmiddlewaretoken',
                    'Flask': r'flask',
                    'Express': r'express',
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
                
                break  # If one protocol works, we have enough info
                
            except Exception as e:
                tech_info[f'{protocol}_error'] = str(e)
                continue
        
        self.results = tech_info
        return tech_info

class PassiveRecon:
    """Main reconnaissance orchestrator"""
    
    def __init__(self, target):
        self.target = target.lower().strip()
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Initialize modules
        self.modules = {
            'dns': DNSEnumerationModule(target, self.session),
            'whois': WHOISModule(target, self.session),
            'subdomains': SubdomainEnumerationModule(target, self.session),
            'webtech': WebTechnologyModule(target, self.session)
        }
    
    def banner(self):
        print("""
╔═══════════════════════════════════════════════════════════════╗
║                ENHANCED PASSIVE RECON TOOL                    ║
║              For Ethical Security Testing                     ║
║          With External API Integration Support                ║
╚═══════════════════════════════════════════════════════════════╝
        """)
    
    def run_module(self, module_name):
        """Run a specific reconnaissance module"""
        if module_name in self.modules:
            try:
                result = self.modules[module_name].execute()
                self.results[module_name] = result
                return result
            except Exception as e:
                print(f"[!] Error running {module_name} module: {e}")
                self.results[module_name] = {'error': str(e)}
                return None
        else:
            print(f"[!] Unknown module: {module_name}")
            return None
    
    def run_all_modules(self):
        """Run all reconnaissance modules"""
        print(f"Starting comprehensive passive reconnaissance for: {self.target}")
        print("="*70)
        
        module_order = ['dns', 'whois', 'subdomains', 'webtech']
        
        for module_name in module_order:
            try:
                self.run_module(module_name)
                time.sleep(2)  # Be respectful to APIs
            except KeyboardInterrupt:
                print("\n[!] Scan interrupted by user")
                break
            except Exception as e:
                print(f"[!] Error in module {module_name}: {e}")
                continue
    
    def generate_report(self):
        """Generate comprehensive JSON and text reports"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # JSON Report
        json_filename = f"passive_recon_{self.target}_{timestamp}.json"
        report_data = {
            'target': self.target,
            'scan_date': datetime.now().isoformat(),
            'results': self.results,
            'summary': {
                'modules_run': list(self.results.keys()),
                'total_subdomains_found': len(self.results.get('subdomains', {}).get('all_subdomains', [])),
                'live_subdomains_found': len(self.results.get('subdomains', {}).get('live_subdomains', [])),
                'scan_successful': len([k for k, v in self.results.items() if not isinstance(v, dict) or 'error' not in v])
            }
        }
        
        with open(json_filename, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        # Text Summary Report
        txt_filename = f"passive_recon_summary_{self.target}_{timestamp}.txt"
        with open(txt_filename, 'w') as f:
            f.write("="*70 + "\n")
            f.write("PASSIVE RECONNAISSANCE REPORT\n")
            f.write("="*70 + "\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*70 + "\n\n")
            
            # Summary
            summary = report_data['summary']
            f.write("SUMMARY:\n")
            f.write(f"- Modules Run: {', '.join(summary['modules_run'])}\n")
            f.write(f"- Total Subdomains Found: {summary['total_subdomains_found']}\n")
            f.write(f"- Live Subdomains Found: {summary['live_subdomains_found']}\n")
            f.write(f"- Successful Modules: {summary['scan_successful']}/{len(summary['modules_run'])}\n\n")
            
            # Live Subdomains
            if 'subdomains' in self.results and 'live_subdomains' in self.results['subdomains']:
                f.write("LIVE SUBDOMAINS:\n")
                for subdomain in self.results['subdomains']['live_subdomains']:
                    f.write(f"- {subdomain}\n")
                f.write("\n")
        
        print("\n" + "="*70)
        print("                    RECONNAISSANCE COMPLETED")
        print("="*70)
        print(f"Target: {self.target}")
        print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Subdomains Found: {report_data['summary']['total_subdomains_found']}")
        print(f"Live Subdomains Found: {report_data['summary']['live_subdomains_found']}")
        print("="*70)
        print(f"\n[+] Detailed JSON report saved to: {json_filename}")
        print(f"[+] Summary report saved to: {txt_filename}")
        
        return report_data

def validate_domain(domain):
    """Validate domain format"""
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, domain)) and len(domain) <= 253

def main():
    parser = argparse.ArgumentParser(
        description='Enhanced Passive Reconnaissance Tool with External API Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com                    # Full passive reconnaissance
  %(prog)s example.com --dns             # DNS enumeration only  
  %(prog)s example.com --whois           # WHOIS lookup only
  %(prog)s example.com --subdomains      # Subdomain enumeration only
  %(prog)s example.com --webtech         # Web technology detection only
        """
    )
    
    parser.add_argument('target', help='Target domain (e.g., example.com)')
    parser.add_argument('--dns', action='store_true', help='DNS enumeration only')
    parser.add_argument('--whois', action='store_true', help='WHOIS lookup only')
    parser.add_argument('--subdomains', action='store_true', help='Subdomain enumeration only')
    parser.add_argument('--webtech', action='store_true', help='Web technology detection only')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    
    args = parser.parse_args()
    
    # Validate target format
    if not validate_domain(args.target):
        print("[!] Invalid domain format. Please use format: example.com")
        sys.exit(1)
    
    # Initialize reconnaissance tool
    recon = PassiveRecon(args.target)
    recon.banner()
    
    # Set timeout for modules
    for module in recon.modules.values():
        if hasattr(module, 'timeout'):
            module.timeout = args.timeout
    
    # Run specific modules or full scan
    try:
        if args.dns:
            recon.run_module('dns')
        elif args.whois:
            recon.run_module('whois')
        elif args.subdomains:
            recon.run_module('subdomains')
        elif args.webtech:
            recon.run_module('webtech')
        else:
            recon.run_all_modules()
        
        # Generate report
        recon.generate_report()
        
    except KeyboardInterrupt:
        print("\n[!] Reconnaissance interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
