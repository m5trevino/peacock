#!/usr/bin/env python3
"""
API Security Analysis Tool
Stage 1-2 Implementation: HAR Parsing + Security Scanning
Built for real street-smart security analysis
"""

import json
import re
import base64
import urllib.parse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
import argparse
import sys

# Third-party imports
try:
    import haralyzer
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, TaskID
    from rich import print as rprint
except ImportError as e:
    print(f"Missing dependencies. Install with: pip install haralyzer rich")
    sys.exit(1)

console = Console()

class HARProcessor:
    """Core HAR file processing engine"""
    
    def __init__(self, har_file_path: str):
        self.har_file_path = Path(har_file_path)
        self.har_data = None
        self.requests = []
        self.stats = defaultdict(int)
        
    def load_har(self) -> bool:
        """Load and validate HAR file"""
        try:
            with open(self.har_file_path, 'r', encoding='utf-8') as f:
                har_content = json.load(f)
            
            self.har_data = haralyzer.HarParser(har_content)
            console.print(f"[green]✓[/green] Loaded HAR file: {self.har_file_path.name}")
            return True
            
        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            console.print(f"[red]✗[/red] Failed to load HAR file: {e}")
            return False
    
    def extract_requests(self) -> List[Dict]:
        """Extract and structure all HTTP requests"""
        if not self.har_data:
            return []
        
        extracted = []
        
        for page in self.har_data.pages:
            for entry in page.entries:
                request_data = {
                    'url': entry.request.url,
                    'method': entry.request.method,
                    'status': entry.response.status,
                    'headers': dict(entry.request.headers),
                    'response_headers': dict(entry.response.headers),
                    'post_data': self._extract_post_data(entry.request),
                    'response_body': self._safe_response_body(entry.response),
                    'timestamp': entry.startedDateTime,
                    'timing': entry.timings,
                    'cookies': [c for c in entry.request.cookies],
                    'domain': urllib.parse.urlparse(entry.request.url).netloc,
                    'path': urllib.parse.urlparse(entry.request.url).path,
                    'query_params': urllib.parse.parse_qs(urllib.parse.urlparse(entry.request.url).query)
                }
                extracted.append(request_data)
                
                # Update stats
                self.stats['total_requests'] += 1
                self.stats[f'method_{entry.request.method}'] += 1
                self.stats[f'status_{entry.response.status}'] += 1
        
        self.requests = extracted
        self.stats['unique_domains'] = len(set(req['domain'] for req in extracted))
        self.stats['unique_paths'] = len(set(req['path'] for req in extracted))
        
        return extracted
    
    def _extract_post_data(self, request) -> Dict:
        """Extract POST data from request"""
        if not hasattr(request, 'postData') or not request.postData:
            return {}
        
        post_data = {
            'mime_type': getattr(request.postData, 'mimeType', ''),
            'text': getattr(request.postData, 'text', ''),
            'params': []
        }
        
        if hasattr(request.postData, 'params'):
            post_data['params'] = [
                {'name': p.name, 'value': p.value} 
                for p in request.postData.params
            ]
        
        return post_data
    
    def _safe_response_body(self, response) -> str:
        """Safely extract response body"""
        try:
            if hasattr(response, 'text') and response.text:
                # Limit response body size to prevent memory issues
                return response.text[:10000] 
        except:
            pass
        return ""

class SecurityScanner:
    """Security vulnerability and secrets scanner"""
    
    def __init__(self):
        self.findings = defaultdict(list)
        self.confidence_scores = {}
        
        # Regex patterns for secrets detection
        self.secret_patterns = {
            'jwt_token': re.compile(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'),
            'api_key': re.compile(r'(?i)(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})'),
            'bearer_token': re.compile(r'Bearer\s+([A-Za-z0-9\-\._~\+\/]+=*)'),
            'auth_token': re.compile(r'(?i)(auth[_-]?token|token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{15,})'),
            'session_id': re.compile(r'(?i)(session[_-]?id|sessionid)["\']?\s*[:=]\s*["\']?([a-f0-9]{20,})'),
            'password': re.compile(r'(?i)(password|pwd)["\']?\s*[:=]\s*["\']?([^"\'\s]{8,})'),
            'secret_key': re.compile(r'(?i)(secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})')
        }
        
        # Vulnerability hint patterns
        self.vuln_patterns = {
            'sql_injection': re.compile(r'(?i)(id|user_?id|order|sort|filter)["\']?\s*[:=]\s*["\']?\d+'),
            'xss_reflection': re.compile(r'(?i)(search|query|message|comment|name)["\']?\s*[:=]'),
            'file_inclusion': re.compile(r'(?i)(file|path|template|include)["\']?\s*[:=]'),
            'command_injection': re.compile(r'(?i)(cmd|command|exec|system)["\']?\s*[:=]'),
            'idor_candidate': re.compile(r'(?i)(user_?id|profile_?id|account_?id)["\']?\s*[:=]\s*["\']?\d+')
        }
        
        # Auth endpoint patterns
        self.auth_patterns = {
            'login': re.compile(r'(?i)/(login|auth|signin|authenticate)'),
            'logout': re.compile(r'(?i)/(logout|signout)'),
            'register': re.compile(r'(?i)/(register|signup|create_account)'),
            'password_reset': re.compile(r'(?i)/(reset|forgot|password)'),
            'oauth': re.compile(r'(?i)/(oauth|sso|saml)')
        }
        
    def scan_requests(self, requests: List[Dict]) -> Dict:
        """Main scanning function"""
        console.print("[cyan]🔍 Starting security scan...[/cyan]")
        
        with Progress() as progress:
            task = progress.add_task("Scanning requests...", total=len(requests))
            
            for req in requests:
                self._scan_secrets(req)
                self._scan_auth_endpoints(req)
                self._scan_vulnerabilities(req)
                self._scan_security_headers(req)
                progress.update(task, advance=1)
        
        return self._compile_findings()
    
    def _scan_secrets(self, request: Dict):
        """Scan for secrets and tokens"""
        # Check headers
        headers_text = json.dumps(request['headers'])
        self._check_patterns_in_text(headers_text, 'secrets', request, 'headers')
        
        # Check POST data
        if request['post_data'].get('text'):
            self._check_patterns_in_text(request['post_data']['text'], 'secrets', request, 'post_data')
        
        # Check URL parameters
        url_params = json.dumps(request['query_params'])
        self._check_patterns_in_text(url_params, 'secrets', request, 'url_params')
        
        # Check response body for reflected secrets
        if request['response_body']:
            self._check_patterns_in_text(request['response_body'], 'secrets', request, 'response')
    
    def _scan_auth_endpoints(self, request: Dict):
        """Identify authentication-related endpoints"""
        url = request['url']
        path = request['path']
        
        for auth_type, pattern in self.auth_patterns.items():
            if pattern.search(path) or pattern.search(url):
                self.findings['auth_endpoints'].append({
                    'type': auth_type,
                    'url': url,
                    'method': request['method'],
                    'status': request['status'],
                    'confidence': 'high'
                })
    
    def _scan_vulnerabilities(self, request: Dict):
        """Scan for vulnerability indicators"""
        # Check URL parameters
        for param, values in request['query_params'].items():
            for vuln_type, pattern in self.vuln_patterns.items():
                if pattern.search(f"{param}={values[0] if values else ''}"):
                    self.findings['vulnerability_hints'].append({
                        'type': vuln_type,
                        'location': 'url_param',
                        'parameter': param,
                        'url': request['url'],
                        'method': request['method'],
                        'confidence': 'medium'
                    })
        
        # Check POST parameters
        if request['post_data'].get('params'):
            for param in request['post_data']['params']:
                for vuln_type, pattern in self.vuln_patterns.items():
                    if pattern.search(f"{param['name']}={param['value']}"):
                        self.findings['vulnerability_hints'].append({
                            'type': vuln_type,
                            'location': 'post_param',
                            'parameter': param['name'],
                            'url': request['url'],
                            'method': request['method'],
                            'confidence': 'medium'
                        })
    
    def _scan_security_headers(self, request: Dict):
        """Check for missing security headers"""
        response_headers = {k.lower(): v for k, v in request['response_headers'].items()}
        
        critical_headers = {
            'content-security-policy': 'CSP header missing',
            'x-frame-options': 'Clickjacking protection missing',
            'x-content-type-options': 'MIME sniffing protection missing',
            'strict-transport-security': 'HSTS header missing',
            'x-xss-protection': 'XSS protection header missing'
        }
        
        for header, description in critical_headers.items():
            if header not in response_headers:
                self.findings['missing_headers'].append({
                    'header': header,
                    'description': description,
                    'url': request['url'],
                    'severity': 'medium'
                })
    
    def _check_patterns_in_text(self, text: str, category: str, request: Dict, location: str):
        """Check text against secret patterns"""
        for pattern_name, pattern in self.secret_patterns.items():
            matches = pattern.findall(text)
            for match in matches:
                match_value = match if isinstance(match, str) else match[1] if len(match) > 1 else match[0]
                
                self.findings[category].append({
                    'type': pattern_name,
                    'value': match_value[:50] + '...' if len(match_value) > 50 else match_value,
                    'location': location,
                    'url': request['url'],
                    'method': request['method'],
                    'confidence': 'high' if pattern_name in ['jwt_token', 'bearer_token'] else 'medium'
                })
    
    def _compile_findings(self) -> Dict:
        """Compile and organize all findings"""
        summary = {
            'total_findings': sum(len(findings) for findings in self.findings.values()),
            'categories': {
                'secrets': len(self.findings['secrets']),
                'auth_endpoints': len(self.findings['auth_endpoints']),
                'vulnerability_hints': len(self.findings['vulnerability_hints']),
                'missing_headers': len(self.findings['missing_headers'])
            },
            'findings': dict(self.findings)
        }
        
        return summary

class EndpointExtractor:
    """Extract endpoints and generate wordlists"""
    
    def __init__(self):
        self.endpoints = defaultdict(set)
        self.parameters = defaultdict(set)
        self.values = defaultdict(list)
    
    def extract_from_requests(self, requests: List[Dict]) -> Dict:
        """Extract endpoint intelligence"""
        console.print("[cyan]🎯 Extracting endpoint intelligence...[/cyan]")
        
        for req in requests:
            # Extract paths
            path = req['path']
            if path and path != '/':
                self.endpoints['paths'].add(path)
                
                # Extract path segments
                segments = [seg for seg in path.split('/') if seg]
                for segment in segments:
                    self.endpoints['segments'].add(segment)
            
            # Extract parameters
            for param in req['query_params'].keys():
                self.parameters['query'].add(param)
            
            if req['post_data'].get('params'):
                for param in req['post_data']['params']:
                    self.parameters['post'].add(param['name'])
                    self.values[param['name']].append(param['value'])
        
        return self._generate_wordlists()
    
    def _generate_wordlists(self) -> Dict:
        """Generate categorized wordlists"""
        wordlists = {
            'endpoints': sorted(list(self.endpoints['paths'])),
            'path_segments': sorted(list(self.endpoints['segments'])),
            'parameters': {
                'query': sorted(list(self.parameters['query'])),
                'post': sorted(list(self.parameters['post']))
            },
            'high_value_targets': self._identify_high_value_targets(),
            'admin_patterns': self._identify_admin_patterns()
        }
        
        return wordlists
    
    def _identify_high_value_targets(self) -> List[str]:
        """Identify high-value endpoints"""
        high_value_keywords = ['admin', 'api', 'internal', 'private', 'config', 'user', 'auth', 'login']
        targets = []
        
        for path in self.endpoints['paths']:
            path_lower = path.lower()
            if any(keyword in path_lower for keyword in high_value_keywords):
                targets.append(path)
        
        return sorted(targets)
    
    def _identify_admin_patterns(self) -> List[str]:
        """Identify potential admin endpoints"""
        admin_keywords = ['admin', 'administrator', 'manage', 'control', 'dashboard', 'panel']
        patterns = []
        
        for path in self.endpoints['paths']:
            path_lower = path.lower()
            if any(keyword in path_lower for keyword in admin_keywords):
                patterns.append(path)
        
        return sorted(patterns)

class ReportGenerator:
    """Generate comprehensive security reports"""
    
    def __init__(self):
        self.console = Console()
    
    def generate_summary_report(self, har_stats: Dict, security_findings: Dict, endpoints: Dict):
        """Generate executive summary"""
        
        # Create summary table
        summary_table = Table(title="🎯 API Security Analysis Summary", show_header=True, header_style="bold cyan")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Count", style="green", justify="right")
        
        summary_table.add_row("Total Requests", str(har_stats.get('total_requests', 0)))
        summary_table.add_row("Unique Domains", str(har_stats.get('unique_domains', 0)))
        summary_table.add_row("Unique Endpoints", str(len(endpoints.get('endpoints', []))))
        summary_table.add_row("Security Findings", str(security_findings.get('total_findings', 0)))
        summary_table.add_row("Secrets Found", str(security_findings['categories'].get('secrets', 0)))
        summary_table.add_row("Auth Endpoints", str(security_findings['categories'].get('auth_endpoints', 0)))
        
        self.console.print(summary_table)
        
        # Security findings breakdown
        if security_findings['total_findings'] > 0:
            self._print_security_findings(security_findings)
        
        # High-value targets
        if endpoints.get('high_value_targets'):
            self._print_high_value_targets(endpoints['high_value_targets'])
    
    def _print_security_findings(self, findings: Dict):
        """Print detailed security findings"""
        
        # Secrets found
        if findings['findings'].get('secrets'):
            secrets_table = Table(title="🔐 Secrets & Tokens Found", show_header=True, header_style="bold red")
            secrets_table.add_column("Type", style="red")
            secrets_table.add_column("Location", style="yellow")
            secrets_table.add_column("URL", style="blue", max_width=50)
            secrets_table.add_column("Confidence", style="green")
            
            for secret in findings['findings']['secrets'][:10]:  # Limit output
                secrets_table.add_row(
                    secret['type'],
                    secret['location'],
                    secret['url'],
                    secret['confidence']
                )
            
            self.console.print(secrets_table)
        
        # Auth endpoints
        if findings['findings'].get('auth_endpoints'):
            auth_table = Table(title="🚪 Authentication Endpoints", show_header=True, header_style="bold yellow")
            auth_table.add_column("Type", style="yellow")
            auth_table.add_column("Method", style="cyan")
            auth_table.add_column("URL", style="blue", max_width=60)
            auth_table.add_column("Status", style="green")
            
            for endpoint in findings['findings']['auth_endpoints']:
                auth_table.add_row(
                    endpoint['type'],
                    endpoint['method'],
                    endpoint['url'],
                    str(endpoint['status'])
                )
            
            self.console.print(auth_table)
    
    def _print_high_value_targets(self, targets: List[str]):
        """Print high-value targets"""
        targets_table = Table(title="🎯 High-Value Targets", show_header=True, header_style="bold magenta")
        targets_table.add_column("Endpoint", style="magenta")
        
        for target in targets[:15]:  # Limit output
            targets_table.add_row(target)
        
        self.console.print(targets_table)
    
    def export_json_report(self, output_file: str, har_stats: Dict, security_findings: Dict, endpoints: Dict):
        """Export comprehensive JSON report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'har_statistics': har_stats,
                'security_summary': security_findings['categories'],
                'total_findings': security_findings['total_findings']
            },
            'security_findings': security_findings['findings'],
            'endpoint_intelligence': endpoints,
            'recommendations': self._generate_recommendations(security_findings, endpoints)
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        console.print(f"[green]✓[/green] JSON report exported: {output_file}")
    
    def export_wordlists(self, output_dir: str, endpoints: Dict):
        """Export wordlists for fuzzing"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        wordlist_files = {
            'endpoints.txt': endpoints.get('endpoints', []),
            'parameters.txt': endpoints.get('parameters', {}).get('query', []) + endpoints.get('parameters', {}).get('post', []),
            'high_value_targets.txt': endpoints.get('high_value_targets', []),
            'admin_patterns.txt': endpoints.get('admin_patterns', [])
        }
        
        for filename, wordlist in wordlist_files.items():
            if wordlist:
                filepath = output_path / filename
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(wordlist))
                console.print(f"[green]✓[/green] Wordlist exported: {filepath}")
    
    def _generate_recommendations(self, security_findings: Dict, endpoints: Dict) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if security_findings['categories'].get('secrets', 0) > 0:
            recommendations.append("🔥 CRITICAL: Secrets found in traffic - immediate rotation required")
        
        if security_findings['categories'].get('missing_headers', 0) > 0:
            recommendations.append("🛡️  Implement missing security headers")
        
        if endpoints.get('high_value_targets'):
            recommendations.append("🎯 Focus testing on identified high-value targets")
        
        if security_findings['categories'].get('vulnerability_hints', 0) > 0:
            recommendations.append("🔍 Manual testing recommended for vulnerability hints")
        
        recommendations.append("📋 Use generated wordlists for comprehensive endpoint discovery")
        
        return recommendations

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description="API Security Analysis Tool")
    parser.add_argument("har_file", help="Path to HAR file")
    parser.add_argument("--output", "-o", help="Output directory", default="./api_security_output")
    parser.add_argument("--export-json", help="Export JSON report", action="store_true")
    parser.add_argument("--export-wordlists", help="Export wordlists", action="store_true")
    parser.add_argument("--quiet", "-q", help="Minimal output", action="store_true")
    
    args = parser.parse_args()
    
    if not args.quiet:
        console.print(Panel.fit(
            "[bold cyan]API Security Analysis Tool[/bold cyan]\n"
            "[yellow]Stage 1-2: HAR Processing + Security Scanning[/yellow]",
            border_style="cyan"
        ))
    
    # Initialize components
    har_processor = HARProcessor(args.har_file)
    security_scanner = SecurityScanner()
    endpoint_extractor = EndpointExtractor()
    report_generator = ReportGenerator()
    
    # Process HAR file
    if not har_processor.load_har():
        return 1
    
    requests = har_processor.extract_requests()
    if not requests:
        console.print("[red]✗[/red] No requests found in HAR file")
        return 1
    
    # Run security scanning
    security_findings = security_scanner.scan_requests(requests)
    
    # Extract endpoint intelligence
    endpoints = endpoint_extractor.extract_from_requests(requests)
    
    # Generate reports
    if not args.quiet:
        report_generator.generate_summary_report(har_processor.stats, security_findings, endpoints)
    
    # Create output directory
    output_path = Path(args.output)
    output_path.mkdir(exist_ok=True)
    
    # Export options
    if args.export_json:
        json_file = output_path / "security_report.json"
        report_generator.export_json_report(str(json_file), har_processor.stats, security_findings, endpoints)
    
    if args.export_wordlists:
        wordlist_dir = output_path / "wordlists"
        report_generator.export_wordlists(str(wordlist_dir), endpoints)
    
    console.print(f"\n[green]✓[/green] Analysis complete. Findings: {security_findings['total_findings']}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
