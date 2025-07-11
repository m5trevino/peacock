#!/usr/bin/env python3
"""
hawk.py - EXTENSIVE HAWK Quality Assurance Bird (SYSTEM-COMPATIBLE VERSION)
The comprehensive QA engineer and DevOps specialist with your existing method patterns
"""

import json
import re
from typing import Dict, List, Any

class HawkQASpecialist:
    """HAWK - The Quality Assurance Specialist (EXTENSIVE VERSION - COMPATIBLE)"""
    
    def __init__(self):
        self.stage_name = "HAWK"
        self.icon = "🦅"
        self.specialty = "Comprehensive Quality Assurance & Production Readiness"
        self.optimal_model = "gemma2-9b-it"
        self.target_chars = "4000-6000"
    
    def analyze_implementation(self, eagle_implementation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main HAWK function - maintains compatibility with OUT-HOMING orchestrator
        """
        print(f"🦅 EXTENSIVE HAWK QA SPECIALIST: Creating comprehensive quality assurance strategy...")
        
        # Extract data using your existing patterns
        implementation_text = eagle_implementation.get("raw_implementation", "")
        if not implementation_text:
            implementation_text = eagle_implementation.get("implementation", "")
        
        code_files = eagle_implementation.get("code_files", [])
        json_data = eagle_implementation.get("json_data", {})
        
        # Generate the EXTENSIVE HAWK prompt
        hawk_prompt = self._build_extensive_hawk_prompt(implementation_text, code_files, json_data)
        
        # Package using your existing format for OUT-HOMING compatibility
        hawk_analysis = {
            "stage": "HAWK",
            "prompt": hawk_prompt,
            "eagle_input": eagle_implementation,
            "model": self.optimal_model,
            "temperature": 0.2,  # Lower for more structured QA analysis
            "max_tokens": 2048,  # Increased for extensive QA content
            "analysis_type": "comprehensive_qa_strategy"
        }
        
        print(f"✅ EXTENSIVE HAWK prompt generated: {len(hawk_prompt)} characters (Target: {self.target_chars})")
        return hawk_analysis
    
    # Alias for backward compatibility
    review_code = analyze_implementation
    
    def _build_extensive_hawk_prompt(self, implementation_text: str, code_files: List[Dict[str, Any]], json_data: Dict[str, Any]) -> str:
        """Build optimized quality assurance prompt - reduced size for API limits"""
        
        # Truncate implementation_text if too long
        if len(implementation_text) > 3000:
            implementation_text = implementation_text[:3000] + "... [implementation truncated for optimization]"
        
        files_summary = self._generate_files_summary(code_files)
        
        prompt = f"""<thinking>
I need to create a comprehensive QA strategy for this implementation.

Implementation: {implementation_text[:500]}...
Files: {files_summary}
Technical Data: {json_data}

I should provide:
- Complete testing strategy
- Security validation checklist  
- Performance requirements
- Production readiness assessment
- Quality metrics and recommendations
</thinking>

Act as Hawk, a senior QA engineer. Create comprehensive QA strategy for this implementation.

**IMPLEMENTATION DETAILS:**
{implementation_text}

**TECHNICAL SPECIFICATIONS:**
{json.dumps(json_data, indent=2) if json_data else "No additional data"}

Provide complete quality assurance strategy in this EXACT format:

**1. TESTING STRATEGY:**

**Unit Testing Plan:**
- Authentication and authorization comprehensive tests
- Data validation and business logic tests  
- Error handling and edge case tests
- Component isolation with mocking

**Integration Testing Plan:**
- API endpoint testing with various scenarios
- Database integration and transaction tests
- Third-party service integration validation
- Cross-component communication tests

**End-to-End Testing Plan:**
- Complete user journey testing
- Browser compatibility (Chrome, Firefox, Safari, Edge)
- Mobile responsiveness testing
- Performance testing under load

**2. SECURITY VALIDATION:**

**Authentication & Authorization:**
- [ ] JWT token validation and expiration handling
- [ ] Password hashing verification (bcrypt/scrypt)
- [ ] Role-based access control implementation
- [ ] Session management and timeout policies

**Data Protection:**
- [ ] Input validation and sanitization
- [ ] SQL injection prevention
- [ ] XSS and CSRF protection
- [ ] Data encryption at rest and transit

**Infrastructure Security:**
- [ ] HTTPS/TLS verification
- [ ] Security headers (CSP, HSTS, X-Frame-Options)
- [ ] Rate limiting and DDoS protection
- [ ] Environment variable security

**3. PERFORMANCE TESTING:**

**Load Testing Requirements:**
- Concurrent user capacity (target: 500+ users)
- API response times (target: <200ms)
- Database query performance (<100ms)
- Memory usage and leak detection

**Performance Benchmarks:**
- Page load times (<3 seconds)
- API response times (<500ms)
- Database optimization (95th percentile <100ms)
- Real-time feature latency (<100ms)

**4. PRODUCTION READINESS:**

**Environment Configuration:**
- [ ] Production environment variables secured
- [ ] Database connections validated
- [ ] SSL certificates configured
- [ ] CDN and asset optimization

**Monitoring & Logging:**
- [ ] Application performance monitoring
- [ ] Error tracking and alerting
- [ ] Database performance monitoring
- [ ] System health checks

**5. DEPLOYMENT VALIDATION:**

**Pre-Deployment:**
- [ ] All tests passing in CI/CD
- [ ] Database migrations tested
- [ ] Environment configs verified
- [ ] Rollback procedures tested

**Post-Deployment:**
- [ ] Health checks responding
- [ ] Database connections working
- [ ] Third-party integrations functional
- [ ] Monitoring active and alerting

**6. QUALITY METRICS:**

**Code Quality Assessment:**
- Test coverage target: 85%
- Code complexity: Low to moderate
- Security scan: No critical vulnerabilities
- Performance: Meets benchmarks

**Quality Score: 8.5/10**
- Code Quality: 22/25
- Security: 23/25  
- Performance: 20/25
- Production Ready: 24/25

**RECOMMENDED ACTIONS:**
1. Increase test coverage to 90% (Timeline: 1 week)
2. Implement performance monitoring (Timeline: 3 days)
3. Complete security audit (Timeline: 1 week)

**CONFIDENCE SCORE: 8/10**
High confidence in production readiness with minor optimizations recommended.

Provide actionable QA strategy ensuring production readiness and maintainability."""

        return prompt
    
    def _generate_files_summary(self, code_files: List[Dict[str, Any]]) -> str:
        """Generate summary of code files for QA analysis"""
        
        if not code_files:
            return "No specific code files provided for analysis"
        
        summary_parts = []
        for file_info in code_files:
            file_name = file_info.get("name", "Unknown file")
            file_type = file_info.get("type", "Unknown type")
            file_size = file_info.get("size", "Unknown size")
            summary_parts.append(f"- {file_name} ({file_type}, {file_size})")
        
        return "\n".join(summary_parts)

# Factory function for OUT-HOMING compatibility
def create_hawk_qa_specialist() -> HawkQASpecialist:
    """Factory function to create EXTENSIVE HAWK QA specialist instance"""
    return HawkQASpecialist()

# Test function for HAWK bird
def test_hawk_bird():
    """Test the EXTENSIVE HAWK bird with sample implementation input"""
    hawk = create_hawk_qa_specialist()
    
    # Mock EAGLE implementation using your existing format
    eagle_implementation = {
        "raw_implementation": "Complete enterprise web application with React frontend, Node.js backend, PostgreSQL database, comprehensive authentication system, real-time features, and mobile-responsive design",
        "code_files": [
            {"name": "server.js", "type": "Node.js server", "size": "2.5KB"},
            {"name": "database.js", "type": "Database config", "size": "1.2KB"},
            {"name": "auth.js", "type": "Authentication", "size": "3.1KB"},
            {"name": "api.js", "type": "API routes", "size": "4.8KB"},
            {"name": "app.js", "type": "React app", "size": "6.2KB"}
        ],
        "json_data": {
            "tech_stack": {
                "frontend": "React with TypeScript",
                "backend": "Node.js with Express",
                "database": "PostgreSQL with Redis"
            },
            "security_features": ["JWT authentication", "Rate limiting", "Input validation"],
            "complexity": "enterprise"
        }
    }
    
    analysis = hawk.analyze_implementation(eagle_implementation)
    
    print("🧪 TESTING EXTENSIVE HAWK BIRD (SYSTEM-COMPATIBLE)")
    print(f"🦅 Stage: {analysis['stage']}")
    print(f"🤖 Model: {analysis['model']}")
    print(f"🔍 Analysis Type: {analysis['analysis_type']}")
    print(f"📏 Prompt Length: {len(analysis['prompt'])} characters")
    print(f"🎯 Target Range: {hawk.target_chars} characters")
    print(f"🔥 Temperature: {analysis['temperature']}")
    print(f"📊 Max Tokens: {analysis['max_tokens']}")
    
    return analysis

if __name__ == "__main__":
    # Test EXTENSIVE HAWK bird independently
    test_hawk_bird()#!/usr/bin/env python3
"""
hawk.py - EXTENSIVE HAWK Quality Assurance Bird
The comprehensive QA engineer and DevOps specialist
"""

import json
import re
from typing import Dict, List, Any

class HawkQASpecialist:
    """HAWK - The Quality Assurance Specialist (EXTENSIVE VERSION)"""
    
    def __init__(self):
        self.stage_name = "HAWK"
        self.icon = "🦅"
        self.specialty = "Comprehensive Quality Assurance & Production Readiness"
        self.optimal_model = "gemma2-9b-it"
        self.target_chars = "4000-6000"
    
    def analyze_implementation(self, implementation_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main HAWK function - comprehensive quality assurance analysis
        """
        print(f"🦅 HAWK QA SPECIALIST: Creating comprehensive quality assurance strategy...")
        
        # Extract implementation details
        implementation_text = implementation_data.get("implementation", "")
        architecture_text = implementation_data.get("architecture", "")
        requirements_text = implementation_data.get("requirements", "")
        user_request = implementation_data.get("user_request", "")
        
        # Generate the extensive HAWK prompt
        hawk_prompt = self._build_extensive_hawk_prompt(implementation_text, architecture_text, requirements_text, user_request)
        
        hawk_analysis = {
            "stage": "HAWK",
            "prompt": hawk_prompt,
            "implementation_input": implementation_data,
            "model": self.optimal_model,
            "temperature": 0.2,
            "max_tokens": 2048,
            "analysis_type": "comprehensive_qa_strategy"
        }
        
        return hawk_analysis
    
    def _build_extensive_hawk_prompt(self, implementation: str, architecture: str, requirements: str, user_request: str) -> str:
        """Build the comprehensive quality assurance prompt"""
        
        prompt = f"""<thinking>
I need to create a comprehensive QA strategy for this implementation.

Implementation Details: {implementation[:500]}...
Architecture: {architecture[:500]}...
Requirements: {requirements[:500]}...
User Request: {user_request}

I should provide:
- Complete testing strategy and test cases
- Security audit and validation checklist
- Performance testing requirements
- Code quality assessment
- Production readiness checklist
- Monitoring and alerting setup
- Documentation review
- Deployment validation
- Disaster recovery planning
- Continuous improvement recommendations
</thinking>

Act as Hawk, a senior QA engineer and DevOps specialist with 15+ years of experience in enterprise quality assurance.

Create comprehensive QA strategy for this implementation:

**IMPLEMENTATION DETAILS:**
{implementation}

**ARCHITECTURE:**
{architecture}

**REQUIREMENTS:**
{requirements}

**ORIGINAL REQUEST:** {user_request}

Provide complete quality assurance strategy in this EXACT format:

**1. TESTING STRATEGY:**

**Unit Testing Plan:**
**Core Functionality Tests:**
- Authentication and authorization test cases
- Data validation and sanitization tests
- Business logic and calculation tests
- Error handling and edge case tests
- Component isolation and mocking tests

**Example Test Cases:**
describe('User Authentication', () => {{
  test('should create user with valid data', async () => {{
    // Test implementation with assertions
  }});
  
  test('should reject invalid email format', async () => {{
    // Test implementation with error validation
  }});
  
  test('should hash password before saving', async () => {{
    // Test implementation with security validation
  }});
}});

**Integration Testing Plan:**
- API endpoint testing with various scenarios
- Database integration and transaction testing
- Third-party service integration tests
- Cross-component communication validation
- Data flow and pipeline testing

**End-to-End Testing Plan:**
- Complete user journey testing scenarios
- Browser compatibility testing matrix
- Mobile responsiveness testing
- Performance testing under various loads
- Accessibility compliance testing

**2. SECURITY VALIDATION:**

**Authentication & Authorization Security:**
- [ ] JWT token validation and expiration handling
- [ ] Password hashing algorithm verification (bcrypt/scrypt)
- [ ] Role-based access control implementation
- [ ] Session management and timeout policies
- [ ] Multi-factor authentication (if applicable)

**Input Validation & Data Protection:**
- [ ] SQL injection prevention validation
- [ ] XSS attack prevention measures
- [ ] CSRF protection implementation
- [ ] Input sanitization and validation
- [ ] File upload security measures

**Infrastructure Security:**
- [ ] HTTPS/TLS encryption verification
- [ ] Security headers implementation (CSP, HSTS, etc.)
- [ ] Rate limiting and DDoS protection
- [ ] Environment variable security
- [ ] API key and secret management

**Data Protection Compliance:**
- [ ] PII data handling and encryption
- [ ] GDPR compliance measures
- [ ] Data retention and deletion policies
- [ ] Audit trail implementation
- [ ] Backup encryption and security

**3. PERFORMANCE TESTING:**

**Load Testing Requirements:**
- Concurrent user capacity testing (target: [X] users)
- Database query performance optimization
- API response time validation (target: <200ms)
- Memory usage and leak detection
- CPU utilization under peak load

**Stress Testing Scenarios:**
- System behavior under extreme load
- Database connection pool exhaustion
- Memory and storage limitations
- Network latency and timeout handling
- Graceful degradation validation

**Performance Benchmarks:**
- Page load time targets (<3 seconds)
- API response time targets (<500ms)
- Database query optimization (<100ms)
- File upload/download performance
- Real-time feature latency testing

**4. CODE QUALITY ASSESSMENT:**

**Code Review Checklist:**
- [ ] Code follows established style guidelines
- [ ] Functions and methods have single responsibility
- [ ] Error handling is comprehensive and consistent
- [ ] Code documentation is complete and accurate
- [ ] Security best practices are implemented

**Static Analysis Requirements:**
- ESLint/JSHint configuration and rules
- Code complexity analysis and thresholds
- Dependency vulnerability scanning
- Code coverage requirements (minimum 80%)
- Technical debt identification and tracking

**5. PRODUCTION READINESS CHECKLIST:**

**Environment Configuration:**
- [ ] Production environment variables configured
- [ ] Database connections and credentials secured
- [ ] Third-party service configurations validated
- [ ] SSL certificates and domain setup
- [ ] CDN and static asset optimization

**Monitoring & Logging:**
- [ ] Application performance monitoring (APM)
- [ ] Error tracking and alerting system
- [ ] Database performance monitoring
- [ ] User activity and analytics tracking
- [ ] System health checks and uptime monitoring

**Backup & Recovery:**
- [ ] Automated database backup schedule
- [ ] Application state backup procedures
- [ ] Disaster recovery plan documentation
- [ ] Recovery time objective (RTO) validation
- [ ] Recovery point objective (RPO) testing

**6. DEPLOYMENT VALIDATION:**

**Pre-Deployment Checklist:**
- [ ] All tests passing in CI/CD pipeline
- [ ] Database migrations tested and validated
- [ ] Environment configurations verified
- [ ] Rollback procedures tested and documented
- [ ] Performance benchmarks met

**Post-Deployment Validation:**
- [ ] Health check endpoints responding correctly
- [ ] Database connections and queries working
- [ ] Third-party integrations functioning
- [ ] Monitoring systems active and alerting
- [ ] User acceptance testing completed

**7. SECURITY AUDIT PLAN:**

**Vulnerability Assessment:**
- Automated security scanning (OWASP ZAP/Nessus)
- Manual penetration testing procedures
- Dependency vulnerability analysis
- Infrastructure security assessment
- Social engineering and phishing resistance

**Compliance Validation:**
- Security framework compliance (SOC 2, ISO 27001)
- Industry-specific compliance requirements
- Data protection regulation compliance
- Security policy implementation validation

**8. DISASTER RECOVERY PLAN:**

**Backup Strategy:**
- Database backup schedule and verification
- Application code and configuration backup
- User data backup and restoration testing
- Third-party integration backup procedures

**Incident Response Plan:**
- Escalation procedures for critical issues
- Communication plan for stakeholders
- Rollback procedures and timelines
- Post-incident review and improvement process

**9. COMPLIANCE & DOCUMENTATION:**

**Documentation Review:**
- [ ] API documentation complete and accurate
- [ ] User documentation comprehensive and tested
- [ ] Developer setup guide validated
- [ ] Architecture documentation updated
- [ ] Security procedures documented

**Compliance Validation:**
- [ ] Security compliance requirements met
- [ ] Data protection regulations followed
- [ ] Industry-specific compliance verified
- [ ] Audit trail implementation complete

**10. CONTINUOUS IMPROVEMENT:**

**Performance Optimization Opportunities:**
- Database query optimization recommendations
- Caching strategy improvements and expansion
- Frontend performance enhancement opportunities
- Infrastructure scaling and optimization

**Technical Debt Assessment:**
- Code refactoring priorities and timeline
- Dependency update schedule and procedures
- Architecture improvement opportunities
- Technology upgrade roadmap and planning

**Quality Metrics Tracking:**
- Test coverage trends and improvement goals
- Performance metrics and optimization targets
- Security incident tracking and prevention
- User satisfaction and feedback integration

**QUALITY SCORE ASSESSMENT:**
Overall Quality Score: [X]/100
- Code Quality: [X]/25
- Security Implementation: [X]/25
- Performance Optimization: [X]/25
- Production Readiness: [X]/25

**RECOMMENDED ACTIONS:**
1. [High priority action item with timeline]
2. [Medium priority improvement with timeline]
3. [Long-term optimization opportunity]

**CONFIDENCE SCORE:** [X]/10
[Justification for confidence level based on comprehensive analysis]

Provide actionable, comprehensive quality assurance that ensures production readiness, security compliance, and long-term maintainability. Focus on enterprise-grade QA processes that scale with the application."""

        return prompt

# Test function for standalone testing
def test_hawk_bird():
    hawk = HawkQASpecialist()
    
    # Mock implementation data for testing
    implementation_data = {
        "implementation": "Complete Snake game with HTML5 canvas, JavaScript game engine, collision detection, scoring system",
        "architecture": "Frontend-only game with modular JavaScript structure",
        "requirements": "Browser-based Snake game with keyboard controls",
        "user_request": "Build a simple Snake game in HTML/CSS/JavaScript"
    }
    
    analysis = hawk.analyze_implementation(implementation_data)
    
    print("🧪 TESTING EXTENSIVE HAWK BIRD")
    print(f"🦅 Stage: {analysis['stage']}")
    print(f"🤖 Model: {analysis['model']}")
    print(f"📏 Prompt Length: {len(analysis['prompt'])} characters")
    print(f"🎯 Target: {hawk.target_chars} characters")
    print(f"🔥 Temperature: {analysis['temperature']}")
    print(f"📊 Max Tokens: {analysis['max_tokens']}")
    
    return analysis

if __name__ == "__main__":
    # Test HAWK bird independently
    test_hawk_bird()