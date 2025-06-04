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
            return severity_weights.get(finding.severity, 40) * finding.confidence
        
        return sorted(self.findings, key=priority_score, reverse=True)

class EndpointIntelligenceEngine:
    """Stage 3: Advanced endpoint intelligence and relationship mapping"""
    
    def __init__(self):
        self.endpoints = {}
        self.api_patterns = {}
        self.data_flows = defaultdict(list)
        self.versioning_info = {}
        
    def analyze_endpoint_intelligence(self, requests: List[Dict], relationships: Dict) -> Dict:
        """Comprehensive endpoint analysis"""
        console.print("[cyan]🎯 Analyzing endpoint intelligence...[/cyan]")
        
        # Build comprehensive endpoint map
        endpoint_map = self._build_endpoint_map(requests)
        
        # Analyze API patterns
        api_patterns = self._analyze_api_patterns(requests)
        
        # Detect versioning schemes
        versioning = self._detect_api_versioning(requests)
        
        # Analyze parameter patterns
        parameter_intelligence = self._analyze_parameter_patterns(requests)
        
        # Generate smart wordlists
        wordlists = self._generate_intelligent_wordlists(endpoint_map, api_patterns)
        
        # Identify high-value targets
        high_value_targets = self._identify_high_value_targets(endpoint_map, requests)
        
        return {
            'endpoint_map': endpoint_map,
            'api_patterns': api_patterns,
            'versioning': versioning,
            'parameter_intelligence': parameter_intelligence,
            'wordlists': wordlists,
            'high_value_targets': high_value_targets,
            'attack_surface_summary': self._generate_attack_surface_summary(endpoint_map)
        }
    
    def _build_endpoint_map(self, requests: List[Dict]) -> Dict[str, APIEndpoint]:
        """Build comprehensive endpoint mapping"""
        endpoint_data = defaultdict(lambda: {
            'methods': set(),
            'status_codes': set(),
            'parameters': defaultdict(set),
            'headers': {},
            'response_types': set(),
            'timings': [],
            'auth_indicators': [],
            'vulnerability_hints': set(),
            'occurrences': 0
        })
        
        for req in requests:
            path = req['path']
            if not path or path == '/':
                continue
            
            # Normalize path (remove query params, standardize dynamic segments)
            normalized_path = self._normalize_path(path)
            
            data = endpoint_data[normalized_path]
            data['methods'].add(req['method'])
            data['status_codes'].add(req['status'])
            data['occurrences'] += 1
            data['response_types'].add(req.get('content_type', '').split(';')[0])
            
            # Extract timing information
            if req.get('timing'):
                total_time = sum(req['timing'].get(k, 0) for k in ['wait', 'receive'])
                data['timings'].append(total_time)
            
            # Analyze parameters
            for param, values in req['query_params'].items():
                data['parameters'][param].update(values)
            
            if req['post_data'].get('form_data'):
                for param, value in req['post_data']['form_data'].items():
                    data['parameters'][param].add(str(value))
            
            # Check for authentication indicators
            if self._has_auth_indicators(req):
                data['auth_indicators'].append(req['method'])
            
            # Collect interesting headers
            for header, value in req['headers'].items():
                if header.lower() in ['authorization', 'x-api-key', 'x-auth-token']:
                    data['headers'][header] = 'PRESENT'
        
        # Convert to APIEndpoint objects
        endpoints = {}
        for path, data in endpoint_data.items():
            avg_timing = sum(data['timings']) / len(data['timings']) if data['timings'] else 0
            
            endpoints[path] = APIEndpoint(
                path=path,
                method=','.join(sorted(data['methods'])),
                status_codes=sorted(list(data['status_codes'])),
                parameters={k: list(v) for k, v in data['parameters'].items()},
                headers=data['headers'],
                auth_required=bool(data['auth_indicators']),
                security_level=self._assess_security_level(path, data),
                response_types=list(data['response_types']),
                timing_avg=avg_timing,
                occurrence_count=data['occurrences'],
                related_endpoints=[],
                vulnerability_hints=list(data['vulnerability_hints'])
            )
        
        return endpoints
    
    def _normalize_path(self, path: str) -> str:
        """Normalize path by replacing dynamic segments"""
        # Replace numeric IDs with placeholder
        path = re.sub(r'/\d+', '/{id}', path)
        
        # Replace UUIDs with placeholder
        path = re.sub(r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '/{uuid}', path)
        
        # Replace other potential dynamic segments
        path = re.sub(r'/[a-f0-9]{32}', '/{hash}', path)  # MD5-like hashes
        path = re.sub(r'/[a-zA-Z0-9]{20,}', '/{token}', path)  # Long tokens
        
        return path
    
    def _analyze_api_patterns(self, requests: List[Dict]) -> Dict:
        """Analyze API design patterns"""
        patterns = {
            'rest_patterns': defaultdict(int),
            'graphql_usage': 0,
            'rpc_patterns': defaultdict(int),
            'naming_conventions': defaultdict(int),
            'common_prefixes': Counter(),
            'resource_patterns': defaultdict(set)
        }
        
        for req in requests:
            path = req['path'].lower()
            method = req['method']
            
            # REST pattern analysis
            if method == 'GET' and '/api/' in path:
                patterns['rest_patterns']['GET_api'] += 1
            elif method == 'POST' and path.endswith('s'):  # Collection endpoints
                patterns['rest_patterns']['POST_collection'] += 1
            elif method in ['PUT', 'PATCH'] and re.search(r'/\d+, path):
                patterns['rest_patterns']['UPDATE_resource'] += 1
            elif method == 'DELETE' and re.search(r'/\d+, path):
                patterns['rest_patterns']['DELETE_resource'] += 1
            
            # GraphQL detection
            if 'graphql' in path or (method == 'POST' and 'query' in req['post_data'].get('text', '')):
                patterns['graphql_usage'] += 1
            
            # RPC pattern detection
            if any(keyword in path for keyword in ['action', 'method', 'do', 'execute']):
                patterns['rpc_patterns']['action_based'] += 1
            
            # Naming convention analysis
            if '_' in path:
                patterns['naming_conventions']['snake_case'] += 1
            elif '-' in path:
                patterns['naming_conventions']['kebab_case'] += 1
            elif re.search(r'[a-z][A-Z]', path):
                patterns['naming_conventions']['camelCase'] += 1
            
            # Common prefixes
            parts = [p for p in path.split('/') if p]
            if parts:
                patterns['common_prefixes'][parts[0]] += 1
            
            # Resource pattern analysis
            for part in parts:
                if part in ['users', 'user', 'accounts', 'account']:
                    patterns['resource_patterns']['user_management'].add(path)
                elif part in ['admin', 'administration', 'manage']:
                    patterns['resource_patterns']['administration'].add(path)
                elif part in ['api', 'v1', 'v2', 'v3']:
                    patterns['resource_patterns']['versioned_api'].add(path)
        
        return patterns
    
    def _detect_api_versioning(self, requests: List[Dict]) -> Dict:
        """Detect API versioning schemes"""
        versioning = {
            'url_versioning': defaultdict(int),
            'header_versioning': defaultdict(int),
            'parameter_versioning': defaultdict(int),
            'versions_detected': set(),
            'versioning_strategy': 'unknown'
        }
        
        version_patterns = [
            re.compile(r'/v(\d+)'),
            re.compile(r'/version[_-]?(\d+)'),
            re.compile(r'/api/(\d+)'),
        ]
        
        for req in requests:
            path = req['path']
            
            # URL-based versioning
            for pattern in version_patterns:
                match = pattern.search(path)
                if match:
                    version = match.group(1)
                    versioning['url_versioning'][f'v{version}'] += 1
                    versioning['versions_detected'].add(f'v{version}')
            
            # Header-based versioning
            for header, value in req['headers'].items():
                if 'version' in header.lower() or 'accept' in header.lower():
                    if 'v' in value:
                        versioning['header_versioning'][value] += 1
            
            # Parameter-based versioning
            for param, values in req['query_params'].items():
                if 'version' in param.lower() or param.lower() == 'v':
                    for value in values:
                        versioning['parameter_versioning'][value] += 1
                        versioning['versions_detected'].add(value)
        
        # Determine primary versioning strategy
        if versioning['url_versioning']:
            versioning['versioning_strategy'] = 'url_based'
        elif versioning['header_versioning']:
            versioning['versioning_strategy'] = 'header_based'
        elif versioning['parameter_versioning']:
            versioning['versioning_strategy'] = 'parameter_based'
        
        return versioning
    
    def _analyze_parameter_patterns(self, requests: List[Dict]) -> Dict:
        """Analyze parameter usage patterns"""
        param_analysis = {
            'common_parameters': Counter(),
            'parameter_types': defaultdict(set),
            'injection_candidates': [],
            'pagination_patterns': set(),
            'filtering_patterns': set(),
            'sorting_patterns': set()
        }
        
        for req in requests:
            # Query parameters
            for param, values in req['query_params'].items():
                param_analysis['common_parameters'][param] += 1
                
                # Analyze parameter types
                for value in values:
                    if value.isdigit():
                        param_analysis['parameter_types'][param].add('numeric')
                    elif self._is_uuid(value):
                        param_analysis['parameter_types'][param].add('uuid')
                    elif '@' in value:
                        param_analysis['parameter_types'][param].add('email')
                    else:
                        param_analysis['parameter_types'][param].add('string')
                
                # Detect common patterns
                if param.lower() in ['page', 'offset', 'limit', 'size']:
                    param_analysis['pagination_patterns'].add(param)
                elif param.lower() in ['filter', 'search', 'q', 'query']:
                    param_analysis['filtering_patterns'].add(param)
                elif param.lower() in ['sort', 'order', 'orderby']:
                    param_analysis['sorting_patterns'].add(param)
                elif param.lower() in ['id', 'user_id', 'account_id']:
                    param_analysis['injection_candidates'].append({
                        'parameter': param,
                        'type': 'IDOR_candidate',
                        'example_values': values[:3]
                    })
            
            # POST parameters
            if req['post_data'].get('form_data'):
                for param, value in req['post_data']['form_data'].items():
                    param_analysis['common_parameters'][param] += 1
        
        return param_analysis
    
    def _generate_intelligent_wordlists(self, endpoint_map: Dict, api_patterns: Dict) -> Dict:
        """Generate intelligent wordlists based on discovered patterns"""
        wordlists = {
            'discovered_endpoints': [],
            'extrapolated_endpoints': [],
            'parameter_names': [],
            'admin_candidates': [],
            'api_candidates': [],
            'version_candidates': [],
            'resource_candidates': []
        }
        
        # Discovered endpoints
        for path in endpoint_map.keys():
            clean_path = path.replace('/{id}', '').replace('/{uuid}', '').replace('/{token}', '').replace('/{hash}', '')
            if clean_path and clean_path != '/':
                wordlists['discovered_endpoints'].append(clean_path.lstrip('/'))
        
        # Extrapolate based on patterns
        base_paths = set()
        for path in endpoint_map.keys():
            parts = [p for p in path.split('/') if p and not p.startswith('{')]
            if parts:
                base_paths.add(parts[0])
        
        # Generate variations
        common_suffixes = ['s', 'list', 'all', 'search', 'filter', 'admin', 'manage']
        for base in base_paths:
            for suffix in common_suffixes:
                candidate = f"{base}/{suffix}" if not base.endswith('s') else f"{base[:-1]}/{suffix}"
                wordlists['extrapolated_endpoints'].append(candidate)
        
        # Parameter names from analysis
        for endpoint in endpoint_map.values():
            wordlists['parameter_names'].extend(endpoint.parameters.keys())
        
        # Admin candidates
        admin_patterns = ['admin', 'administrator', 'manage', 'control', 'dashboard', 'panel']
        for pattern in admin_patterns:
            for base in base_paths:
                wordlists['admin_candidates'].extend([
                    f"{pattern}/{base}",
                    f"{base}/{pattern}",
                    f"{pattern}"
                ])
        
        # API version candidates
        if api_patterns.get('versioning', {}).get('versions_detected'):
            for version in api_patterns['versioning']['versions_detected']:
                wordlists['version_candidates'].extend([
                    f"api/{version}",
                    f"{version}/api",
                    version
                ])
        
        # Remove duplicates and sort
        for key in wordlists:
            wordlists[key] = sorted(list(set(wordlists[key])))
        
        return wordlists
    
    def _identify_high_value_targets(self, endpoint_map: Dict, requests: List[Dict]) -> List[Dict]:
        """Identify high-value targets for focused testing"""
        targets = []
        
        for path, endpoint in endpoint_map.items():
            score = 0
            reasons = []
            
            # Authentication required
            if endpoint.auth_required:
                score += 30
                reasons.append("Authentication required")
            
            # Admin-related paths
            if any(keyword in path.lower() for keyword in ['admin', 'manage', 'control', 'dashboard']):
                score += 50
                reasons.append("Administrative interface")
            
            # API endpoints
            if '/api/' in path:
                score += 20
                reasons.append("API endpoint")
            
            # User data endpoints
            if any(keyword in path.lower() for keyword in ['user', 'profile', 'account']):
                score += 25
                reasons.append("User data access")
            
            # Direct object references
            if '/{id}' in path or '/{uuid}' in path:
                score += 35
                reasons.append("Direct object reference")
            
            # Multiple HTTP methods
            methods = endpoint.method.split(',')
            if len(methods) > 1:
                score += 15
                reasons.append(f"Multiple methods: {endpoint.method}")
            
            # Sensitive parameters
            sensitive_params = ['password', 'token', 'key', 'secret', 'admin']
            if any(param in sensitive_params for param in endpoint.parameters.keys()):
                score += 40
                reasons.append("Sensitive parameters")
            
            # High frequency (popular endpoints)
            if endpoint.occurrence_count > 10:
                score += 10
                reasons.append("High traffic endpoint")
            
            if score >= 30:  # Threshold for high-value
                targets.append({
                    'path': path,
                    'score': score,
                    'reasons': reasons,
                    'methods': endpoint.method,
                    'security_level': endpoint.security_level,
                    'parameters': list(endpoint.parameters.keys())
                })
        
        return sorted(targets, key=lambda x: x['score'], reverse=True)
    
    def _assess_security_level(self, path: str, data: Dict) -> str:
        """Assess security level of endpoint"""
        if any(keyword in path.lower() for keyword in ['admin', 'internal', 'private']):
            return 'high'
        elif data['auth_indicators']:
            return 'medium'
        elif '/api/' in path:
            return 'medium'
        else:
            return 'low'
    
    def _has_auth_indicators(self, request: Dict) -> bool:
        """Check if request has authentication indicators"""
        auth_headers = ['authorization', 'x-api-key', 'x-auth-token', 'bearer']
        headers_lower = {k.lower(): v for k, v in request['headers'].items()}
        
        return any(header in headers_lower for header in auth_headers)
    
    def _is_uuid(self, value: str) -> bool:
        """Check if value is a UUID"""
        uuid_pattern = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})
        return bool(uuid_pattern.match(value))
    
    def _generate_attack_surface_summary(self, endpoint_map: Dict) -> Dict:
        """Generate attack surface summary"""
        summary = {
            'total_endpoints': len(endpoint_map),
            'authenticated_endpoints': sum(1 for ep in endpoint_map.values() if ep.auth_required),
            'high_security_endpoints': sum(1 for ep in endpoint_map.values() if ep.security_level == 'high'),
            'endpoints_with_parameters': sum(1 for ep in endpoint_map.values() if ep.parameters),
            'unique_parameters': len(set(param for ep in endpoint_map.values() for param in ep.parameters.keys())),
            'methods_distribution': Counter(method for ep in endpoint_map.values() for method in ep.method.split(',')),
            'avg_response_time': sum(ep.timing_avg for ep in endpoint_map.values()) / len(endpoint_map) if endpoint_map else 0
        }
        
        return summary

class FlowAnalysisEngine:
    """Stage 4: API flow analysis and process mapping"""
    
    def __init__(self):
        self.flows = []
        self.process_chains = defaultdict(list)
        self.session_flows = defaultdict(list)
        
    def analyze_api_flows(self, requests: List[Dict], relationships: Dict, 
                         security_findings: List[SecurityFinding]) -> Dict:
        """Analyze API flows and multi-step processes"""
        console.print("[cyan]🔄 Analyzing API flows and processes...[/cyan]")
        
        # Detect authentication flows
        auth_flows = self._detect_authentication_flows(requests)
        
        # Detect business process flows
        business_flows = self._detect_business_processes(requests, relationships)
        
        # Analyze data flow patterns
        data_flows = self._analyze_data_flows(requests, relationships)
        
        # Detect error handling patterns
        error_patterns = self._analyze_error_patterns(requests)
        
        # Generate flow documentation
        flow_documentation = self._generate_flow_documentation(
            auth_flows, business_flows, data_flows
        )
        
        return {
            'authentication_flows': auth_flows,
            'business_processes': business_flows,
            'data_flows': data_flows,
            'error_patterns': error_patterns,
            'flow_documentation': flow_documentation,
            'session_analysis': self._analyze_session_patterns(requests),
            'critical_paths': self._identify_critical_paths(requests, security_findings)
        }
    
    def _detect_authentication_flows(self, requests: List[Dict]) -> List[APIFlow]:
        """Detect authentication flow patterns"""
        auth_flows = []
        current_flow = []
        
        auth_keywords = ['login', 'auth', 'signin', 'authenticate', 'token', 'logout', 'register']
        
        for i, req in enumerate(requests):
            url_lower = req['url'].lower()
            
            if any(keyword in url_lower for keyword in auth_keywords):
                current_flow.append({
                    'step': len(current_flow) + 1,
                    'request_id': req['id'],
                    'method': req['method'],
                    'url': req['url'],
                    'status': req['status'],
                    'timing': req.get('timing', {}),
                    'has_credentials': self._has_credentials(req),
                    'generates_token': self._generates_token(req),
                    'redirects': req['status'] in [301, 302, 303, 307, 308]
                })
                
                # Check if flow is complete
                if self._is_auth_flow_complete(req, current_flow):
                    flow = APIFlow(
                        flow_id=str(uuid.uuid4())[:8],
                        name=self._classify_auth_flow_type(current_flow),
                        steps=current_flow.copy(),
                        flow_type='authentication',
                        authentication_required=True,
                        data_flow=self._extract_auth_data_flow(current_flow),
                        completion_indicators=self._get_auth_completion_indicators(current_flow)
                    )
                    auth_flows.append(flow)
                    current_flow = []
        
        return auth_flows
    
    def _detect_business_processes(self, requests: List[Dict], relationships: Dict) -> List[APIFlow]:
        """Detect business process flows"""
        business_flows = []
        
        # Group requests by session
        session_groups = defaultdict(list)
        for req in requests:
            session_id = req.get('session_id', 'default')
            session_groups[session_id].append(req)
        
        for session_id, session_requests in session_groups.items():
            if len(session_requests) < 3:  # Skip short sessions
                continue
            
            # Detect process patterns
            processes = self._identify_process_patterns(session_requests)
            
            for process in processes:
                flow = APIFlow(
                    flow_id=str(uuid.uuid4())[:8],
                    name=process['name'],
                    steps=process['steps'],
                    flow_type='business_process',
                    authentication_required=process.get('auth_required', False),
                    data_flow=process.get('data_flow', []),
                    completion_indicators=process.get('completion_indicators', [])
                )
                business_flows.append(flow)
        
        return business_flows
    
    def _analyze_data_flows(self, requests: List[Dict], relationships: Dict) -> Dict:
        """Analyze how data flows between requests"""
        data_flows = {
            'parameter_propagation': [],
            'response_to_request_flow': [],
            'session_data_flow': [],
            'cross_endpoint_data': []
        }
        
        for req_id, related_requests in relationships.items():
            source_req = next((r for r in requests if r['id'] == req_id), None)
            if not source_req:
                continue
            
            for relationship in related_requests:
                if relationship['type'] == 'data_flow':
                    target_req = next((r for r in requests if r['id'] == relationship['target']), None)
                    if target_req:
                        flow_info = {
                            'source': {
                                'id': source_req['id'],
                                'url': source_req['url'],
                                'method': source_req['method']
                            },
                            'target': {
                                'id': target_req['id'],
                                'url': target_req['url'],
                                'method': target_req['method']
                            },
                            'confidence': relationship['confidence'],
                            'data_elements': self._identify_shared_data_elements(source_req, target_req)
                        }
                        data_flows['response_to_request_flow'].append(flow_info)
        
        return data_flows
    
    def _analyze_error_patterns(self, requests: List[Dict]) -> Dict:
        """Analyze error handling patterns"""
        error_patterns = {
            'error_responses': defaultdict(list),
            'error_endpoints': defaultdict(int),
            'common_error_codes': Counter(),
            'error_handling_quality': 'unknown'
        }
        
        for req in requests:
            if req['status'] >= 400:
                error_code = req['status']
                error_patterns['common_error_codes'][error_code] += 1
                error_patterns['error_endpoints'][req['path']] += 1
                
                error_info = {
                    'url': req['url'],
                    'method': req['method'],
                    'status': req['status'],
                    'response_body': req['response_body'][:500] if req['response_body'] else ''
                }
                error_patterns['error_responses'][error_code].append(error_info)
        
        # Assess error handling quality
        total_requests = len(requests)
        error_requests = sum(error_patterns['common_error_codes'].values())
        error_rate = error_requests / total_requests if total_requests > 0 else 0
        
        if error_rate < 0.05:
            error_patterns['error_handling_quality'] = 'good'
        elif error_rate < 0.15:
            error_patterns['error_handling_quality'] = 'moderate'
        else:
            error_patterns['error_handling_quality'] = 'poor'
        
        return error_patterns
    
    def _generate_flow_documentation(self, auth_flows: List[APIFlow], 
                                   business_flows: List[APIFlow], data_flows: Dict) -> str:
        """Generate comprehensive flow documentation"""
        doc_sections = []
        
        # Authentication flows section
        if auth_flows:
            doc_sections.append("# Authentication Flows\n")
            for flow in auth_flows:
                doc_sections.append(f"## {flow.name}\n")
                doc_sections.append(f"**Flow ID:** {flow.flow_id}\n")
                doc_sections.append(f"**Steps:** {len(flow.steps)}\n\n")
                
                for step in flow.steps:
                    doc_sections.append(f"{step['step']}. **{step['method']}** {step['url']}")
                    doc_sections.append(f"   - Status: {step['status']}")
                    if step.get('has_credentials'):
                        doc_sections.append("   - Contains credentials")
                    if step.get('generates_token'):
                        doc_sections.append("   - Generates authentication token")
                    doc_sections.append("")
                
                doc_sections.append("---\n")
        
        # Business processes section
        if business_flows:
            doc_sections.append("# Business Process Flows\n")
            for flow in business_flows:
                doc_sections.append(f"## {flow.name}\n")
                doc_sections.append(f"**Process Type:** {flow.flow_type}\n")
                doc_sections.append(f"**Authentication Required:** {flow.authentication_required}\n\n")
                
                for step in flow.steps:
                    doc_sections.append(f"{step['step']}. **{step['method']}** {step['url']}")
                    doc_sections.append(f"   - Status: {step['status']}")
                    doc_sections.append("")
                
                doc_sections.append("---\n")
        
        # Data flow analysis
        if data_flows.get('response_to_request_flow'):
            doc_sections.append("# Data Flow Analysis\n")
            doc_sections.append("## Response-to-Request Data Flow\n")
            
            for flow in data_flows['response_to_request_flow']:
                doc_sections.append(f"**{flow['source']['method']}** {flow['source']['url']}")
                doc_sections.append(f"↓ (confidence: {flow['confidence']:.2f})")
                doc_sections.append(f"**{flow['target']['method']}** {flow['target']['url']}")
                if flow['data_elements']:
                    doc_sections.append(f"Data elements: {', '.join(flow['data_elements'])}")
                doc_sections.append("")
        
        return "\n".join(doc_sections)
    
    def _has_credentials(self, request: Dict) -> bool:
        """Check if request contains credentials"""
        credential_indicators = ['username', 'password', 'email', 'login', 'credentials']
        
        # Check POST data
        post_text = request['post_data'].get('text', '').lower()
        if any(indicator in post_text for indicator in credential_indicators):
            return True
        
        # Check form data
        form_data = request['post_data'].get('form_data', {})
        if any(indicator in key.lower() for key in form_data.keys() for indicator in credential_indicators):
            return True
        
        return False
    
    def _generates_token(self, request: Dict) -> bool:
        """Check if response generates authentication token"""
        response_body = request.get('response_body', '').lower()
        token_indicators = ['token', 'jwt', 'bearer', 'access_token', 'session_id']
        
        return any(indicator in response_body for indicator in token_indicators)

class VisualMappingEngine:
    """Stage 5: Visual mapping and interactive analysis"""
    
    def __init__(self):
        self.mermaid_diagrams = {}
        self.html_reports = {}
        
    def generate_visual_maps(self, intelligence_data: Dict, flow_data: Dict, 
                           security_findings: List[SecurityFinding]) -> Dict:
        """Generate comprehensive visual maps"""
        console.print("[cyan]🎨 Generating visual maps and reports...[/cyan]")
        
        # Generate Mermaid diagrams
        mermaid_diagrams = {
            'api_structure': self._generate_api_structure_diagram(intelligence_data),
            'authentication_flows': self._generate_auth_flow_diagrams(flow_data),
            'security_overview': self._generate_security_overview_diagram(security_findings),
            'data_flow_diagram': self._generate_data_flow_diagram(flow_data)
        }
        
        # Generate interactive HTML report
        html_report = self._generate_interactive_html_report(
            intelligence_data, flow_data, security_findings, mermaid_diagrams