# config.py - Configuration management
"""
Configuration settings for API Security Scanner
Customize patterns, thresholds, and analysis parameters
"""

class SecurityConfig:
    """Security scanning configuration"""
    
    # Confidence thresholds
    HIGH_CONFIDENCE_THRESHOLD = 0.8
    MEDIUM_CONFIDENCE_THRESHOLD = 0.5
    
    # Pattern sensitivity
    SECRET_MIN_LENGTH = 15
    TOKEN_MIN_LENGTH = 20
    
    # Output limits
    MAX_FINDINGS_PER_CATEGORY = 100
    MAX_RESPONSE_BODY_SIZE = 10000
    
    # Custom secret patterns (add your own)
    CUSTOM_SECRET_PATTERNS = {
        'slack_token': r'xox[baprs]-[0-9a-zA-Z-]{10,}',
        'github_token': r'gh[pousr]_[A-Za-z0-9_]{36}',
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'stripe_key': r'sk_live_[0-9a-zA-Z]{24}',
        'twilio_sid': r'AC[a-z0-9]{32}',
        'firebase_url': r'https://[a-z0-9-]+\.firebaseio\.com'
    }
    
    # High-value endpoint keywords
    HIGH_VALUE_KEYWORDS = [
        'admin', 'api', 'internal', 'private', 'config', 
        'user', 'auth', 'login', 'dashboard', 'manage',
        'control', 'panel', 'settings', 'profile'
    ]
    
    # Vulnerability hint patterns
    VULN_HINT_PATTERNS = {
        'potential_sqli': [
            r'(?i)(id|user_?id|order|sort|filter)["\']?\s*[:=]\s*["\']?\d+',
            r'(?i)(select|union|from|where)\s+.{1,50}',
        ],
        'potential_xss': [
            r'(?i)(search|query|message|comment|name|title)["\']?\s*[:=]',
            r'<script[^>]*>.*?</script>',
        ],
        'potential_lfi': [
            r'(?i)(file|path|template|include|page)["\']?\s*[:=].*\.(php|jsp|asp)',
            r'\.\.\/.*\.(conf|log|passwd)',
        ]
    }

# utils.py - Utility functions
"""
Utility functions for API Security Scanner
"""

import re
import json
import hashlib
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Any, Optional

def sanitize_secret(secret: str, show_chars: int = 6) -> str:
    """Safely display secrets with masking"""
    if len(secret) <= show_chars * 2:
        return secret[:3] + '*' * (len(secret) - 3)
    return secret[:show_chars] + '*' * 8 + secret[-show_chars:]

def extract_domain_info(url: str) -> Dict[str, str]:
    """Extract detailed domain information"""
    parsed = urlparse(url)
    return {
        'domain': parsed.netloc,
        'subdomain': parsed.netloc.split('.')[0] if '.' in parsed.netloc else '',
        'tld': '.'.join(parsed.netloc.split('.')[-2:]) if '.' in parsed.netloc else parsed.netloc,
        'scheme': parsed.scheme,
        'port': str(parsed.port) if parsed.port else ''
    }

def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string"""
    if not data:
        return 0
    
    entropy = 0
    for char in set(data):
        freq = data.count(char) / len(data)
        entropy -= freq * (freq.bit_length() - 1) if freq > 0 else 0
    
    return entropy

def is_likely_secret(value: str, min_entropy: float = 3.5) -> bool:
    """Determine if a value is likely a secret based on entropy"""
    if len(value) < 10:
        return False
    
    entropy = calculate_entropy(value)
    return entropy >= min_entropy

def extract_json_keys(json_text: str) -> List[str]:
    """Extract all keys from JSON text"""
    try:
        data = json.loads(json_text)
        return extract_keys_recursive(data)
    except:
        return []

def extract_keys_recursive(obj: Any, keys: List[str] = None) -> List[str]:
    """Recursively extract keys from nested objects"""
    if keys is None:
        keys = []
    
    if isinstance(obj, dict):
        for key, value in obj.items():
            keys.append(key)
            extract_keys_recursive(value, keys)
    elif isinstance(obj, list):
        for item in obj:
            extract_keys_recursive(item, keys)
    
    return keys

def hash_request(url: str, method: str, body: str = '') -> str:
    """Create unique hash for request deduplication"""
    content = f"{method}:{url}:{body}"
    return hashlib.md5(content.encode()).hexdigest()[:12]

# advanced_scanners.py - Extended scanning capabilities
"""
Advanced security scanners for specialized detection
"""

import re
import base64
import json
from typing import Dict, List, Any
from config import SecurityConfig

class AdvancedSecretScanner:
    """Enhanced secret detection with context analysis"""
    
    def __init__(self):
        self.config = SecurityConfig()
        self.patterns = self._build_comprehensive_patterns()
    
    def _build_comprehensive_patterns(self) -> Dict[str, re.Pattern]:
        """Build comprehensive secret patterns"""
        patterns = {}
        
        # Merge default and custom patterns
        all_patterns = {
            **self.config.CUSTOM_SECRET_PATTERNS,
            'generic_high_entropy': r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64-like
            'hex_key': r'[a-f0-9]{32,}',  # Hex keys
            'uuid_pattern': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        }
        
        for name, pattern in all_patterns.items():
            patterns[name] = re.compile(pattern, re.IGNORECASE)
        
        return patterns
    
    def scan_with_context(self, text: str, context: Dict) -> List[Dict]:
        """Scan text with contextual analysis"""
        findings = []
        
        for pattern_name, pattern in self.patterns.items():
            matches = pattern.finditer(text)
            
            for match in matches:
                value = match.group(0)
                
                # Skip if too short
                if len(value) < self.config.SECRET_MIN_LENGTH:
                    continue
                
                # Calculate confidence based on context
                confidence = self._calculate_confidence(value, context, pattern_name)
                
                if confidence >= self.config.MEDIUM_CONFIDENCE_THRESHOLD:
                    findings.append({
                        'type': pattern_name,
                        'value': value,
                        'confidence': confidence,
                        'position': match.span(),
                        'context': context
                    })
        
        return findings
    
    def _calculate_confidence(self, value: str, context: Dict, pattern_type: str) -> float:
        """Calculate confidence score for secret detection"""
        base_confidence = 0.5
        
        # Pattern-specific confidence
        if pattern_type in ['jwt_token', 'bearer_token']:
            base_confidence = 0.9
        elif pattern_type in ['slack_token', 'github_token', 'aws_access_key']:
            base_confidence = 0.85
        
        # Context boosts
        if context.get('location') == 'headers':
            base_confidence += 0.1
        
        if 'auth' in context.get('url', '').lower():
            base_confidence += 0.1
        
        # Entropy check
        if is_likely_secret(value):
            base_confidence += 0.15
        
        return min(base_confidence, 1.0)

class AuthFlowAnalyzer:
    """Analyze authentication flows and patterns"""
    
    def __init__(self):
        self.flows = {}
        self.sessions = {}
    
    def analyze_auth_sequence(self, requests: List[Dict]) -> Dict:
        """Analyze authentication sequences"""
        auth_flows = []
        current_flow = []
        
        for req in requests:
            if self._is_auth_related(req):
                current_flow.append({
                    'step': len(current_flow) + 1,
                    'method': req['method'],
                    'url': req['url'],
                    'status': req['status'],
                    'has_auth_header': self._has_auth_header(req),
                    'redirects': req['status'] in [301, 302, 303, 307, 308]
                })
                
                # Detect flow completion
                if self._is_flow_complete(req):
                    auth_flows.append({
                        'flow_id': len(auth_flows) + 1,
                        'steps': current_flow.copy(),
                        'flow_type': self._classify_flow_type(current_flow)
                    })
                    current_flow = []
        
        return {'auth_flows': auth_flows}
    
    def _is_auth_related(self, request: Dict) -> bool:
        """Check if request is authentication-related"""
        auth_indicators = [
            'login', 'auth', 'signin', 'authenticate', 'oauth',
            'sso', 'saml', 'logout', 'signout', 'register'
        ]
        
        url_lower = request['url'].lower()
        return any(indicator in url_lower for indicator in auth_indicators)
    
    def _has_auth_header(self, request: Dict) -> bool:
        """Check for authentication headers"""
        headers = {k.lower(): v for k, v in request['headers'].items()}
        auth_headers = ['authorization', 'x-auth-token', 'x-api-key']
        return any(header in headers for header in auth_headers)
    
    def _is_flow_complete(self, request: Dict) -> bool:
        """Determine if auth flow is complete"""
        # Success indicators
        if request['status'] == 200 and 'dashboard' in request['url'].lower():
            return True
        if request['status'] in [301, 302] and 'home' in request['url'].lower():
            return True
        return False
    
    def _classify_flow_type(self, flow_steps: List[Dict]) -> str:
        """Classify the type of authentication flow"""
        urls = [step['url'].lower() for step in flow_steps]
        
        if any('oauth' in url for url in urls):
            return 'oauth'
        elif any('saml' in url for url in urls):
            return 'saml'
        elif any('register' in url for url in urls):
            return 'registration'
        else:
            return 'standard_login'

# export_manager.py - Advanced export capabilities
"""
Export manager for various output formats
"""

import json
import csv
from pathlib import Path
from typing import Dict, List, Any

class ExportManager:
    """Manage exports in multiple formats"""
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def export_csv_findings(self, findings: Dict) -> str:
        """Export findings to CSV format"""
        csv_file = self.output_dir / "security_findings.csv"
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow(['Category', 'Type', 'Value', 'URL', 'Method', 'Confidence', 'Location'])
            
            # Write findings
            for category, items in findings.items():
                for item in items:
                    writer.writerow([
                        category,
                        item.get('type', ''),
                        item.get('value', '')[:100],  # Truncate long values
                        item.get('url', ''),
                        item.get('method', ''),
                        item.get('confidence', ''),
                        item.get('location', '')
                    ])
        
        return str(csv_file)
    
    def export_burp_wordlist(self, endpoints: List[str]) -> str:
        """Export endpoints in Burp-compatible format"""
        burp_file = self.output_dir / "burp_endpoints.txt"
        
        # Format for Burp Intruder
        formatted_endpoints = []
        for endpoint in endpoints:
            if endpoint.startswith('/'):
                formatted_endpoints.append(endpoint[1:])  # Remove leading slash
            else:
                formatted_endpoints.append(endpoint)
        
        with open(burp_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(set(formatted_endpoints))))
        
        return str(burp_file)
    
    def export_postman_collection(self, requests: List[Dict]) -> str:
        """Export requests as Postman collection"""
        collection = {
            "info": {
                "name": "API Security Scanner Export",
                "description": "Exported from HAR analysis",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": []
        }
        
        # Group by domain
        domain_groups = {}
        for req in requests[:50]:  # Limit to first 50 requests
            domain = req.get('domain', 'unknown')
            if domain not in domain_groups:
                domain_groups[domain] = []
            
            domain_groups[domain].append({
                "name": f"{req['method']} {req['path']}",
                "request": {
                    "method": req['method'],
                    "header": [{"key": k, "value": v} for k, v in req['headers'].items()],
                    "url": {
                        "raw": req['url'],
                        "host": [domain],
                        "path": req['path'].split('/')[1:] if req['path'] else []
                    }
                }
            })
        
        # Add to collection
        for domain, items in domain_groups.items():
            collection["item"].append({
                "name": domain,
                "item": items
            })
        
        postman_file = self.output_dir / "postman_collection.json"
        with open(postman_file, 'w', encoding='utf-8') as f:
            json.dump(collection, f, indent=2)
        
        return str(postman_file)

# test_runner.py - Testing and validation
"""
Test suite for API Security Scanner
"""

import json
import tempfile
from pathlib import Path

def create_test_har() -> str:
    """Create a test HAR file for validation"""
    test_har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1.0"},
            "pages": [{
                "startedDateTime": "2024-01-01T00:00:00Z",
                "id": "page_1",
                "title": "Test Page",
                "pageTimings": {}
            }],
            "entries": [
                {
                    "pageref": "page_1",
                    "startedDateTime": "2024-01-01T00:00:00Z",
                    "time": 100,
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/auth/login",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token"},
                            {"name": "Content-Type", "value": "application/json"}
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"username": "test", "password": "secret123", "api_key": "sk_live_abcdef123456789"}'
                        }
                    },
                    "response": {
                        "status": 200,
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"},
                            {"name": "Set-Cookie", "value": "session_id=abc123def456; HttpOnly"}
                        ],
                        "content": {
                            "text": '{"success": true, "token": "jwt_token_here"}'
                        }
                    },
                    "timings": {"wait": 50, "receive": 50}
                }
            ]
        }
    }
    
    # Write to temporary file
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.har', delete=False)
    json.dump(test_har, temp_file, indent=2)
    temp_file.close()
    
    return temp_file.name

def run_basic_test():
    """Run basic functionality test"""
    print("🧪 Running API Security Scanner Tests...")
    
    # Create test HAR
    test_har_file = create_test_har()
    
    try:
        # Import and test main components
        from api_security_tool import HARProcessor, SecurityScanner, EndpointExtractor
        
        # Test HAR processing
        processor = HARProcessor(test_har_file)
        assert processor.load_har(), "Failed to load test HAR file"
        
        requests = processor.extract_requests()
        assert len(requests) > 0, "No requests extracted"
        
        # Test security scanning
        scanner = SecurityScanner()
        findings = scanner.scan_requests(requests)
        assert findings['total_findings'] > 0, "No security findings detected"
        
        # Test endpoint extraction
        extractor = EndpointExtractor()
        endpoints = extractor.extract_from_requests(requests)
        assert len(endpoints['endpoints']) > 0, "No endpoints extracted"
        
        print("✅ All tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False
    
    finally:
        # Cleanup
        Path(test_har_file).unlink(missing_ok=True)

if __name__ == "__main__":
    run_basic_test()
