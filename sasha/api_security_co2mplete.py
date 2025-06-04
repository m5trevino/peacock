#!/usr/bin/env python3
"""
API Security Analysis Tool - Complete Implementation
Stages 1-5: HAR Processing → Security Scanning → Intelligence → Analysis → Visual Mapping
Built for real street-smart security analysis
"""

import json
import re
import base64
import urllib.parse
import hashlib
import uuid
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
import argparse
import sys
import time
import webbrowser
import tempfile

# Third-party imports
try:
    import haralyzer
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, TaskID
    from rich.tree import Tree
    from rich.layout import Layout
    from rich.live import Live
    from rich.markdown import Markdown
    from rich import print as rprint
except ImportError as e:
    print(f"Missing dependencies. Install with: pip install haralyzer rich")
    sys.exit(1)

console = Console()

@dataclass
class APIEndpoint:
    """Structured endpoint representation"""
    path: str
    method: str
    status_codes: List[int]
    parameters: Dict[str, List[str]]
    headers: Dict[str, str]
    auth_required: bool
    security_level: str
    response_types: List[str]
    timing_avg: float
    occurrence_count: int
    related_endpoints: List[str]
    vulnerability_hints: List[str]

@dataclass
class APIFlow:
    """Represents a sequence of API calls"""
    flow_id: str
    name: str
    steps: List[Dict]
    flow_type: str
    authentication_required: bool
    data_flow: List[str]
    completion_indicators: List[str]

@dataclass
class SecurityFinding:
    """Enhanced security finding with context"""
    finding_id: str
    category: str
    severity: str
    confidence: float
    title: str
    description: str
    location: Dict[str, Any]
    evidence: str
    recommendations: List[str]
    related_endpoints: List[str]

class AdvancedHARProcessor:
    """Enhanced HAR processing with relationship detection"""
    
    def __init__(self, har_file_path: str):
        self.har_file_path = Path(har_file_path)
        self.har_data = None
        self.requests = []
        self.sessions = defaultdict(list)
        self.request_relationships = defaultdict(list)
        self.stats = defaultdict(int)
        
    def load_har(self) -> bool:
        """Load and validate HAR file with enhanced parsing"""
        try:
            with open(self.har_file_path, 'r', encoding='utf-8') as f:
                har_content = json.load(f)
            
            self.har_data = haralyzer.HarParser(har_content)
            console.print(f"[green]✓[/green] Loaded HAR file: {self.har_file_path.name}")
            return True
            
        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            console.print(f"[red]✗[/red] Failed to load HAR file: {e}")
            return False
    
    def extract_requests_with_relationships(self) -> List[Dict]:
        """Extract requests and detect relationships"""
        if not self.har_data:
            return []
        
        extracted = []
        session_tokens = {}
        
        for page in self.har_data.pages:
            for entry in page.entries:
                request_data = {
                    'id': str(uuid.uuid4())[:8],
                    'url': entry.request.url,
                    'method': entry.request.method,
                    'status': entry.response.status,
                    'headers': dict(entry.request.headers),
                    'response_headers': dict(entry.response.headers),
                    'post_data': self._extract_enhanced_post_data(entry.request),
                    'response_body': self._safe_response_body(entry.response),
                    'timestamp': entry.startedDateTime,
                    'timing': entry.timings,
                    'cookies': [c for c in entry.request.cookies],
                    'domain': urllib.parse.urlparse(entry.request.url).netloc,
                    'path': urllib.parse.urlparse(entry.request.url).path,
                    'query_params': urllib.parse.parse_qs(urllib.parse.urlparse(entry.request.url).query),
                    'session_indicators': self._extract_session_indicators(entry),
                    'referrer': self._get_referrer(entry.request),
                    'content_type': self._get_content_type(entry.response),
                    'response_size': len(entry.response.content.text) if hasattr(entry.response.content, 'text') else 0
                }
                
                # Detect session relationships
                session_id = self._identify_session(request_data)
                if session_id:
                    self.sessions[session_id].append(request_data['id'])
                    request_data['session_id'] = session_id
                
                extracted.append(request_data)
                
                # Update enhanced stats
                self._update_enhanced_stats(request_data)
        
        self.requests = extracted
        self._detect_request_relationships()
        return extracted
    
    def _extract_enhanced_post_data(self, request) -> Dict:
        """Enhanced POST data extraction with JSON parsing"""
        if not hasattr(request, 'postData') or not request.postData:
            return {}
        
        post_data = {
            'mime_type': getattr(request.postData, 'mimeType', ''),
            'text': getattr(request.postData, 'text', ''),
            'params': [],
            'json_data': {},
            'form_data': {}
        }
        
        # Parse form parameters
        if hasattr(request.postData, 'params'):
            post_data['params'] = [
                {'name': p.name, 'value': p.value} 
                for p in request.postData.params
            ]
            post_data['form_data'] = {p.name: p.value for p in request.postData.params}
        
        # Parse JSON data
        if post_data['text'] and 'json' in post_data['mime_type']:
            try:
                post_data['json_data'] = json.loads(post_data['text'])
            except:
                pass
        
        return post_data
    
    def _extract_session_indicators(self, entry) -> Dict:
        """Extract session-related indicators"""
        indicators = {
            'cookies': [],
            'tokens': [],
            'session_id': None
        }
        
        # Check cookies for session indicators
        for cookie in entry.request.cookies:
            if any(keyword in cookie.name.lower() for keyword in ['session', 'auth', 'token']):
                indicators['cookies'].append({'name': cookie.name, 'value': cookie.value[:20] + '...'})
                if 'session' in cookie.name.lower():
                    indicators['session_id'] = cookie.value
        
        # Check headers for tokens
        headers = dict(entry.request.headers)
        if 'Authorization' in headers:
            indicators['tokens'].append(headers['Authorization'][:30] + '...')
        
        return indicators
    
    def _identify_session(self, request_data: Dict) -> Optional[str]:
        """Identify session ID for request grouping"""
        # Try cookies first
        for cookie in request_data['cookies']:
            if 'session' in cookie.name.lower():
                return cookie.value
        
        # Try authorization header
        auth_header = request_data['headers'].get('Authorization', '')
        if auth_header:
            return hashlib.md5(auth_header.encode()).hexdigest()[:12]
        
        # Fallback to IP-based grouping
        return request_data['domain']
    
    def _detect_request_relationships(self):
        """Detect relationships between requests"""
        for i, req in enumerate(self.requests):
            for j, other_req in enumerate(self.requests[i+1:], i+1):
                # Check for data flow relationships
                if self._has_data_relationship(req, other_req):
                    self.request_relationships[req['id']].append({
                        'target': other_req['id'],
                        'type': 'data_flow',
                        'confidence': 0.8
                    })
                
                # Check for sequence relationships
                if self._is_sequence_related(req, other_req):
                    self.request_relationships[req['id']].append({
                        'target': other_req['id'],
                        'type': 'sequence',
                        'confidence': 0.6
                    })
    
    def _has_data_relationship(self, req1: Dict, req2: Dict) -> bool:
        """Check if one request's response data appears in another's request"""
        if not req1['response_body'] or not req2['post_data']['text']:
            return False
        
        try:
            # Look for response data in subsequent request
            response_data = json.loads(req1['response_body'])
            request_data = req2['post_data']['text']
            
            # Check if any response values appear in request
            for value in self._extract_values_recursive(response_data):
                if str(value) in request_data:
                    return True
        except:
            pass
        
        return False
    
    def _is_sequence_related(self, req1: Dict, req2: Dict) -> bool:
        """Check if requests are part of a logical sequence"""
        # Same session and close timing
        if (req1.get('session_id') == req2.get('session_id') and 
            req1.get('session_id') is not None):
            time_diff = abs(
                datetime.fromisoformat(req2['timestamp'].replace('Z', '+00:00')).timestamp() -
                datetime.fromisoformat(req1['timestamp'].replace('Z', '+00:00')).timestamp()
            )
            return time_diff < 30  # Within 30 seconds
        
        return False
    
    def _extract_values_recursive(self, obj: Any) -> List[Any]:
        """Recursively extract all values from nested objects"""
        values = []
        if isinstance(obj, dict):
            for value in obj.values():
                values.extend(self._extract_values_recursive(value))
        elif isinstance(obj, list):
            for item in obj:
                values.extend(self._extract_values_recursive(item))
        else:
            values.append(obj)
        return values
    
    def _update_enhanced_stats(self, request_data: Dict):
        """Update enhanced statistics"""
        self.stats['total_requests'] += 1
        self.stats[f'method_{request_data["method"]}'] += 1
        self.stats[f'status_{request_data["status"]}'] += 1
        self.stats[f'domain_{request_data["domain"]}'] += 1
        
        if request_data.get('session_id'):
            self.stats['requests_with_session'] += 1
        
        if request_data['post_data']['json_data']:
            self.stats['json_requests'] += 1
    
    def _get_referrer(self, request) -> str:
        """Extract referrer information"""
        headers = dict(request.headers)
        return headers.get('Referer', headers.get('Referrer', ''))
    
    def _get_content_type(self, response) -> str:
        """Extract response content type"""
        headers = dict(response.headers)
        return headers.get('Content-Type', '').split(';')[0]
    
    def _safe_response_body(self, response) -> str:
        """Safely extract response body"""
        try:
            if hasattr(response, 'text') and response.text:
                return response.text[:50000]  # Increased limit for better analysis
        except:
            pass
        return ""

class EnhancedSecurityScanner:
    """Stage 2: Enhanced security scanning with advanced pattern detection"""
    
    def __init__(self):
        self.findings = []
        self.patterns = self._build_comprehensive_patterns()
        self.context_analyzers = self._build_context_analyzers()
        
    def _build_comprehensive_patterns(self) -> Dict[str, Dict]:
        """Build comprehensive security patterns"""
        return {
            'secrets': {
                'jwt_token': {
                    'pattern': re.compile(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'),
                    'severity': 'high',
                    'confidence_base': 0.9
                },
                'api_key_generic': {
                    'pattern': re.compile(r'(?i)(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})'),
                    'severity': 'high',
                    'confidence_base': 0.8
                },
                'bearer_token': {
                    'pattern': re.compile(r'Bearer\s+([A-Za-z0-9\-\._~\+\/]+=*)'),
                    'severity': 'high',
                    'confidence_base': 0.9
                },
                'aws_access_key': {
                    'pattern': re.compile(r'AKIA[0-9A-Z]{16}'),
                    'severity': 'critical',
                    'confidence_base': 0.95
                },
                'github_token': {
                    'pattern': re.compile(r'gh[pousr]_[A-Za-z0-9_]{36}'),
                    'severity': 'high',
                    'confidence_base': 0.9
                },
                'slack_token': {
                    'pattern': re.compile(r'xox[baprs]-[0-9a-zA-Z-]{10,}'),
                    'severity': 'high',
                    'confidence_base': 0.9
                },
                'stripe_key': {
                    'pattern': re.compile(r'sk_live_[0-9a-zA-Z]{24}'),
                    'severity': 'critical',
                    'confidence_base': 0.95
                },
                'database_uri': {
                    'pattern': re.compile(r'(?i)(mongodb|mysql|postgresql|redis)://[^\s\'"]+'),
                    'severity': 'critical',
                    'confidence_base': 0.9
                },
                'private_key': {
                    'pattern': re.compile(r'-----BEGIN [A-Z ]+PRIVATE KEY-----'),
                    'severity': 'critical',
                    'confidence_base': 0.95
                }
            },
            'vulnerabilities': {
                'sql_injection': {
                    'patterns': [
                        re.compile(r"(?i)(union|select|from|where|insert|update|delete)\s+.{1,50}"),
                        re.compile(r"(?i)(id|user_?id|order|sort)['\"]?\s*[:=]\s*['\"]?\d+['\"]?\s*(and|or|union)"),
                        re.compile(r"['\"].*['\"].*(\bor\b|\band\b).*[=<>]")
                    ],
                    'severity': 'high',
                    'confidence_base': 0.7
                },
                'xss_reflection': {
                    'patterns': [
                        re.compile(r'(?i)(search|query|message|comment|name|title)["\']?\s*[:=].*<.*>'),
                        re.compile(r'<script[^>]*>.*?</script>'),
                        re.compile(r'javascript:[^"\']*'),
                        re.compile(r'on(load|error|click)[^=]*=[^>]*>')
                    ],
                    'severity': 'medium',
                    'confidence_base': 0.6
                },
                'command_injection': {
                    'patterns': [
                        re.compile(r'(?i)(cmd|command|exec|system)["\']?\s*[:=].*[;&|]'),
                        re.compile(r'[;&|]\s*(cat|ls|dir|ping|wget|curl)'),
                        re.compile(r'\$\([^)]+\)'),
                        re.compile(r'`[^`]+`')
                    ],
                    'severity': 'critical',
                    'confidence_base': 0.8
                },
                'path_traversal': {
                    'patterns': [
                        re.compile(r'\.\.\/.*\.(conf|log|passwd|shadow)'),
                        re.compile(r'(?i)(file|path|include)["\']?\s*[:=].*\.\.\/'),
                        re.compile(r'\/etc\/(passwd|shadow|hosts)'),
                        re.compile(r'\.\.\\.*\.(ini|conf)')
                    ],
                    'severity': 'high',
                    'confidence_base': 0.8
                },
                'idor_candidate': {
                    'patterns': [
                        re.compile(r'(?i)(user_?id|profile_?id|account_?id|doc_?id)["\']?\s*[:=]\s*["\']?\d+'),
                        re.compile(r'\/users?\/\d+'),
                        re.compile(r'\/profiles?\/\d+'),
                        re.compile(r'\/documents?\/[a-f0-9-]{36}')  # UUID pattern
                    ],
                    'severity': 'medium',
                    'confidence_base': 0.6
                }
            },
            'authentication': {
                'login_endpoint': re.compile(r'(?i)\/(login|auth|signin|authenticate|logon)'),
                'logout_endpoint': re.compile(r'(?i)\/(logout|signout|logoff)'),
                'register_endpoint': re.compile(r'(?i)\/(register|signup|create[_-]?account)'),
                'password_reset': re.compile(r'(?i)\/(reset|forgot|password|recover)'),
                'oauth_endpoint': re.compile(r'(?i)\/(oauth|sso|saml|openid)'),
                'admin_endpoint': re.compile(r'(?i)\/(admin|administrator|manage|control|dashboard)'),
                'api_endpoint': re.compile(r'(?i)\/api\/'),
                'internal_endpoint': re.compile(r'(?i)\/(internal|private|restricted)')
            }
        }
    
    def _build_context_analyzers(self) -> Dict:
        """Build context analysis functions"""
        return {
            'entropy_analysis': self._analyze_entropy,
            'frequency_analysis': self._analyze_frequency,
            'response_reflection': self._analyze_response_reflection,
            'session_analysis': self._analyze_session_context
        }
    
    def scan_requests_enhanced(self, requests: List[Dict], relationships: Dict) -> List[SecurityFinding]:
        """Enhanced security scanning with context analysis"""
        console.print("[cyan]🔍 Starting enhanced security scan...[/cyan]")
        
        with Progress() as progress:
            task = progress.add_task("Deep scanning requests...", total=len(requests))
            
            for req in requests:
                # Core security scans
                self._scan_secrets_enhanced(req)
                self._scan_vulnerabilities_enhanced(req)
                self._scan_authentication_patterns(req)
                self._scan_authorization_bypass(req)
                self._scan_data_exposure(req)
                self._scan_security_headers_comprehensive(req)
                
                # Context-aware analysis
                self._analyze_request_context(req, relationships.get(req['id'], []))
                
                progress.update(task, advance=1)
        
        return self._prioritize_findings()
    
    def _scan_secrets_enhanced(self, request: Dict):
        """Enhanced secret detection with context"""
        locations = {
            'headers': json.dumps(request['headers']),
            'url_params': json.dumps(request['query_params']),
            'post_data': request['post_data'].get('text', ''),
            'response_body': request['response_body'],
            'cookies': str(request['cookies'])
        }
        
        for location, content in locations.items():
            if not content:
                continue
                
            for secret_type, pattern_info in self.patterns['secrets'].items():
                matches = pattern_info['pattern'].findall(content)
                
                for match in matches:
                    value = match if isinstance(match, str) else match[1] if len(match) > 1 else match[0]
                    
                    if len(value) < 10:  # Skip short matches
                        continue
                    
                    # Enhanced confidence calculation
                    confidence = self._calculate_enhanced_confidence(
                        value, location, secret_type, pattern_info, request
                    )
                    
                    if confidence >= 0.5:
                        finding = SecurityFinding(
                            finding_id=str(uuid.uuid4())[:8],
                            category='secrets',
                            severity=pattern_info['severity'],
                            confidence=confidence,
                            title=f"{secret_type.replace('_', ' ').title()} Detected",
                            description=f"Potential {secret_type} found in {location}",
                            location={
                                'request_id': request['id'],
                                'url': request['url'],
                                'method': request['method'],
                                'location': location,
                                'position': content.find(value)
                            },
                            evidence=self._sanitize_evidence(value),
                            recommendations=self._get_secret_recommendations(secret_type),
                            related_endpoints=[request['url']]
                        )
                        self.findings.append(finding)
    
    def _scan_vulnerabilities_enhanced(self, request: Dict):
        """Enhanced vulnerability detection"""
        # Combine all searchable content
        searchable_content = {
            'url': request['url'],
            'post_data': request['post_data'].get('text', ''),
            'response_body': request['response_body'],
            'headers': json.dumps(request['headers'])
        }
        
        for vuln_type, vuln_info in self.patterns['vulnerabilities'].items():
            patterns = vuln_info['patterns'] if isinstance(vuln_info['patterns'], list) else [vuln_info['patterns']]
            
            for location, content in searchable_content.items():
                if not content:
                    continue
                
                for pattern in patterns:
                    matches = pattern.findall(content)
                    
                    if matches:
                        confidence = self._calculate_vuln_confidence(vuln_type, location, content, request)
                        
                        if confidence >= 0.4:
                            finding = SecurityFinding(
                                finding_id=str(uuid.uuid4())[:8],
                                category='vulnerability_hint',
                                severity=vuln_info['severity'],
                                confidence=confidence,
                                title=f"Potential {vuln_type.replace('_', ' ').title()}",
                                description=f"Pattern indicating possible {vuln_type} vulnerability",
                                location={
                                    'request_id': request['id'],
                                    'url': request['url'],
                                    'method': request['method'],
                                    'location': location,
                                    'matches': matches[:3]  # Limit matches
                                },
                                evidence=content[:200] + '...' if len(content) > 200 else content,
                                recommendations=self._get_vuln_recommendations(vuln_type),
                                related_endpoints=[request['url']]
                            )
                            self.findings.append(finding)
    
    def _scan_authorization_bypass(self, request: Dict):
        """Scan for authorization bypass opportunities"""
        # Check for direct object references
        if re.search(r'\/\d+$', request['path']):
            # Numeric ID at end of path
            finding = SecurityFinding(
                finding_id=str(uuid.uuid4())[:8],
                category='authorization',
                severity='medium',
                confidence=0.6,
                title="Direct Object Reference",
                description="Endpoint uses direct numeric references - test for IDOR",
                location={
                    'request_id': request['id'],
                    'url': request['url'],
                    'method': request['method']
                },
                evidence=f"Path: {request['path']}",
                recommendations=[
                    "Test with different numeric IDs",
                    "Verify authorization for accessed objects",
                    "Implement proper access controls"
                ],
                related_endpoints=[request['url']]
            )
            self.findings.append(finding)
    
    def _scan_data_exposure(self, request: Dict):
        """Scan for sensitive data exposure"""
        sensitive_patterns = {
            'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            'phone': re.compile(r'[\+]?[1-9]?[0-9]{7,15}'),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'credit_card': re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
            'ip_address': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        }
        
        content = request['response_body']
        if not content:
            return
        
        for data_type, pattern in sensitive_patterns.items():
            matches = pattern.findall(content)
            if len(matches) > 5:  # Multiple instances suggest systematic exposure
                finding = SecurityFinding(
                    finding_id=str(uuid.uuid4())[:8],
                    category='data_exposure',
                    severity='medium',
                    confidence=0.7,
                    title=f"Potential {data_type.title()} Exposure",
                    description=f"Multiple {data_type} patterns found in response",
                    location={
                        'request_id': request['id'],
                        'url': request['url'],
                        'method': request['method']
                    },
                    evidence=f"Found {len(matches)} instances of {data_type} patterns",
                    recommendations=[
                        "Review data minimization practices",
                        "Implement proper data filtering",
                        "Consider data masking for sensitive fields"
                    ],
                    related_endpoints=[request['url']]
                )
                self.findings.append(finding)
    
    def _calculate_enhanced_confidence(self, value: str, location: str, secret_type: str, 
                                     pattern_info: Dict, request: Dict) -> float:
        """Calculate enhanced confidence score"""
        base_confidence = pattern_info['confidence_base']
        
        # Location-based adjustments
        if location == 'headers' and secret_type in ['bearer_token', 'api_key_generic']:
            base_confidence += 0.1
        elif location == 'response_body':
            base_confidence -= 0.2  # Might be example/documentation
        
        # Context adjustments
        if 'auth' in request['url'].lower() or 'login' in request['url'].lower():
            base_confidence += 0.1
        
        # Entropy analysis
        entropy = self._calculate_entropy(value)
        if entropy > 4.0:
            base_confidence += 0.1
        elif entropy < 2.0:
            base_confidence -= 0.2
        
        # Length analysis
        if len(value) > 50:
            base_confidence += 0.05
        elif len(value) < 20:
            base_confidence -= 0.1
        
        return min(base_confidence, 1.0)
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0
        
        entropy = 0
        for char in set(data):
            freq = data.count(char) / len(data)
            entropy -= freq * (freq.bit_length() - 1) if freq > 0 else 0
        
        return entropy
    
    def _sanitize_evidence(self, value: str) -> str:
        """Sanitize evidence for safe display"""
        if len(value) <= 12:
            return value[:6] + '*' * (len(value) - 6)
        return value[:8] + '*' * 8 + value[-8:]
    
    def _get_secret_recommendations(self, secret_type: str) -> List[str]:
        """Get recommendations for secret types"""
        recommendations = {
            'jwt_token': [
                "Immediately rotate the JWT signing key",
                "Review token expiration policies",
                "Implement proper token storage practices"
            ],
            'api_key_generic': [
                "Rotate the API key immediately",
                "Review API key scoping and permissions",
                "Implement rate limiting and monitoring"
            ],
            'aws_access_key': [
                "CRITICAL: Rotate AWS credentials immediately",
                "Review IAM policies and permissions",
                "Enable CloudTrail monitoring for this key"
            ],
            'database_uri': [
                "CRITICAL: Change database credentials immediately",
                "Review database access controls",
                "Implement connection encryption"
            ]
        }
        
        return recommendations.get(secret_type, ["Review and rotate credentials immediately"])
    
    def _get_vuln_recommendations(self, vuln_type: str) -> List[str]:
        """Get recommendations for vulnerability types"""
        recommendations = {
            'sql_injection': [
                "Use parameterized queries/prepared statements",
                "Implement input validation and sanitization",
                "Apply principle of least privilege to database accounts"
            ],
            'xss_reflection': [
                "Implement proper output encoding",
                "Use Content Security Policy (CSP)",
                "Validate and sanitize all user inputs"
            ],
            'command_injection': [
                "Avoid system calls with user input",
                "Use safe APIs instead of shell commands",
                "Implement strict input validation"
            ],
            'path_traversal': [
                "Validate file paths against whitelist",
                "Use safe file access APIs",
                "Implement proper access controls"
            ]
        }
        
        return recommendations.get(vuln_type, ["Implement proper input validation"])
    
    def _prioritize_findings(self) -> List[SecurityFinding]:
        """Prioritize findings by severity and confidence"""
        severity_weights = {'critical': 100, 'high': 80, 'medium': 60, 'low': 40}
        
        def priority_score(finding):
            return severity_weights.get(finding.severity, 40) *