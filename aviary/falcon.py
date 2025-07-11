#!/usr/bin/env python3
"""
falcon.py - EXTENSIVE FALCON Architecture Design Bird (SYSTEM-COMPATIBLE VERSION)
The comprehensive system architect with your existing factory function pattern
"""

import json
import re
from typing import Dict, List, Any

class FalconArchitect:
    """FALCON - The System Architect (EXTENSIVE VERSION - COMPATIBLE)"""
    
    def __init__(self):
        self.stage_name = "FALCON"
        self.icon = "🦅"
        self.specialty = "Comprehensive Technical Architecture Design"
        self.optimal_model = "gemma2-9b-it"
        self.target_chars = "4000-6000"
    
    def design_architecture(self, spark_requirements: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main FALCON function - maintains compatibility with OUT-HOMING orchestrator
        """
        print(f"🦅 EXTENSIVE FALCON ARCHITECT: Generating comprehensive architecture design...")
        
        # Extract data using your existing patterns
        spark_text = spark_requirements.get("raw_analysis", "")
        if not spark_text:
            spark_text = spark_requirements.get("analysis", "")
        
        requirements_data = spark_requirements.get("json_data", {})
        if not requirements_data:
            requirements_data = spark_requirements.get("analysis", {})
        
        # Generate the EXTENSIVE FALCON prompt
        falcon_prompt = self._build_extensive_falcon_prompt(spark_text, requirements_data)
        
        # Package using your existing format for OUT-HOMING compatibility
        falcon_design = {
            "stage": "FALCON",
            "prompt": falcon_prompt,
            "spark_input": spark_requirements,
            "model": self.optimal_model,
            "temperature": 0.3,
            "max_tokens": 2048,  # Increased for extensive content
            "design_type": "comprehensive_enterprise_architecture"
        }
        
        print(f"✅ EXTENSIVE FALCON prompt generated: {len(falcon_prompt)} characters (Target: {self.target_chars})")
        return falcon_design
    
    def _build_extensive_falcon_prompt(self, spark_text: str, requirements_data: Dict[str, Any]) -> str:
        """Build comprehensive enterprise-grade architecture prompt"""
        
        prompt = f"""<thinking>
I need to design a comprehensive technical architecture based on these requirements from SPARK.

Requirements: {spark_text}
Data: {requirements_data}

I should provide:
- Complete technology stack recommendations with justifications
- Detailed system architecture with all components
- Database design with relationships and data flow
- Complete API specifications with endpoints
- Security architecture with threat model
- Deployment and infrastructure strategy
- Scalability and performance strategy
- Integration patterns and workflows
- Development methodology and CI/CD
- Technical debt considerations and future planning
</thinking>

Act as Falcon, a senior solution architect with 15+ years of experience designing enterprise-grade, scalable applications.

Design the complete technical architecture for this system:

**REQUIREMENTS ANALYSIS:**
{spark_text}

**ADDITIONAL CONTEXT:**
{json.dumps(requirements_data, indent=2) if requirements_data else "No additional structured data"}

Provide comprehensive enterprise architecture design in this EXACT format:

**1. TECHNOLOGY STACK RECOMMENDATIONS:**

**Frontend Technology:**
- Framework: [Specific framework with version and detailed justification]
- UI Component Library: [Library with design system rationale and implementation strategy]
- State Management: [Solution with complexity justification and data flow patterns]
- Build Tools: [Webpack/Vite with configuration rationale and optimization strategy]
- Testing Framework: [Jest/Cypress with comprehensive testing strategy]
- Performance Optimization: [Lazy loading, code splitting, CDN strategies]

**Backend Technology:**
- Runtime Environment: [Node.js/Python with version justification and performance analysis]
- Framework: [Express/Django/FastAPI with detailed feature comparison]
- Authentication: [JWT/OAuth/Session with comprehensive security analysis]
- Validation: [Joi/Yup with data integrity strategy and error handling]
- API Documentation: [Swagger/OpenAPI with maintenance strategy and versioning]
- Background Processing: [Queue system with job scheduling and failure handling]

**Database Strategy:**
- Primary Database: [PostgreSQL/MongoDB with detailed data model justification]
- Caching Layer: [Redis/Memcached with comprehensive caching strategy]
- Search Engine: [Elasticsearch with indexing strategy and query optimization]
- Data Migration: [Migration strategy, versioning, and rollback procedures]

**DevOps & Infrastructure:**
- Containerization: [Docker with orchestration strategy and scaling policies]
- Cloud Platform: [AWS/GCP/Azure with detailed service selection rationale]
- CI/CD Pipeline: [GitHub Actions/Jenkins with comprehensive workflow design]
- Monitoring: [Application and infrastructure monitoring with alerting strategies]

**2. SYSTEM ARCHITECTURE DIAGRAM:**

**High-Level Architecture:**
```
[Browser/Mobile] ↔ [Load Balancer/CDN] ↔ [API Gateway] ↔ [Microservices] ↔ [Database Cluster]
        ↓                    ↓                ↓              ↓                ↓
[PWA Cache]         [SSL Termination]   [Rate Limiting]  [Service Mesh]   [Backup Systems]
        ↓                    ↓                ↓              ↓                ↓
[Offline Support]   [Security Headers]  [Authentication] [Load Balancing]  [Disaster Recovery]
```

**Component Interactions:**
- User authentication and authorization flow with multi-factor support
- Data processing pipeline with real-time and batch processing
- Real-time communication architecture (WebSockets/Server-Sent Events)
- File upload/storage system with CDN integration
- Third-party integrations with circuit breaker patterns

**3. DATABASE DESIGN:**

**Entity Relationship Model:**
```sql
-- Primary entities with comprehensive relationships
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- Additional fields based on requirements
);

CREATE TABLE [business_entities] (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    -- Complete schema design based on domain requirements
);

-- Indexes for performance optimization
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_business_entities_user_id ON [business_entities](user_id);
```

**Data Flow Architecture:**
- CRUD operation patterns with optimistic locking
- Data validation layers with comprehensive error handling
- Query optimization strategy with prepared statements
- Indexing strategy with performance monitoring
- Data archival and retention policy with compliance considerations

**4. API ARCHITECTURE:**

**RESTful API Design:**
```
# User Management
GET    /api/v1/users              # List users with pagination, filtering, sorting
POST   /api/v1/users              # Create user with comprehensive validation
GET    /api/v1/users/:id          # Get user details with privacy controls
PUT    /api/v1/users/:id          # Update user with versioning and audit trail
DELETE /api/v1/users/:id          # Soft delete with audit trail and recovery

# Business Logic Endpoints (based on requirements)
GET    /api/v1/[resources]        # List with advanced filtering and pagination
POST   /api/v1/[resources]        # Create with validation and business rules
GET    /api/v1/[resources]/:id    # Retrieve with access control
PUT    /api/v1/[resources]/:id    # Update with conflict resolution
DELETE /api/v1/[resources]/:id    # Delete with cascade handling

# Administrative Endpoints
GET    /api/v1/admin/metrics      # System metrics and health checks
POST   /api/v1/admin/maintenance  # Maintenance mode controls
GET    /api/v1/admin/logs         # Log access with security controls
```

**API Standards:**
- Request/Response format standardization with JSON:API compliance
- Comprehensive error handling with detailed error codes and messages
- Rate limiting and throttling with different tiers for user types
- API versioning strategy with backward compatibility guarantees
- Complete documentation with interactive API explorer

**5. SECURITY ARCHITECTURE:**

**Authentication & Authorization:**
- Multi-factor authentication with TOTP and backup codes
- Role-based access control (RBAC) with fine-grained permissions
- JWT token management with refresh token rotation
- Session security with secure cookie handling and timeout policies
- OAuth 2.0 integration with social providers and enterprise SSO

**Data Protection:**
- Encryption at rest using AES-256 for database and file storage
- Encryption in transit with TLS 1.3 and certificate pinning
- Comprehensive input validation with whitelist-based sanitization
- SQL injection prevention with parameterized queries and ORM protections
- XSS and CSRF protection with Content Security Policy and token validation

**Infrastructure Security:**
- Network security with VPC, subnets, and security groups
- DDoS protection with rate limiting and traffic analysis
- Security headers implementation (HSTS, CSP, X-Frame-Options)
- Vulnerability scanning with automated security testing in CI/CD
- Penetration testing schedule and security audit procedures

**6. SCALABILITY STRATEGY:**

**Horizontal Scaling:**
- Load balancing strategy with health checks and failover
- Database sharding/partitioning with consistent hashing
- Microservices decomposition with domain-driven design
- CDN and edge computing with global distribution strategy

**Performance Optimization:**
- Multi-level caching strategy (browser, CDN, application, database)
- Database query optimization with query analysis and indexing
- Asset optimization with compression and minification
- Real-time performance monitoring with APM tools and alerting

**7. DEPLOYMENT ARCHITECTURE:**

**Environment Strategy:**
- Development environment with Docker Compose for local development
- Staging environment mirroring production with blue-green deployment
- Production environment with high availability and disaster recovery
- Environment-specific configurations with secret management

**CI/CD Pipeline:**
- Automated testing stages (unit, integration, end-to-end, security)
- Code quality gates with static analysis and coverage requirements
- Deployment automation with rollback capabilities and canary releases
- Infrastructure as Code with Terraform/CloudFormation

**Infrastructure as Code:**
- Container orchestration with Kubernetes or Docker Swarm
- Infrastructure provisioning with automated scaling policies
- Configuration management with centralized secret storage
- Monitoring and alerting setup with PagerDuty/Slack integration

**8. INTEGRATION STRATEGY:**

**Third-Party Integrations:**
- Payment processing with PCI compliance and fraud detection
- Email and notification services with template management
- Analytics and monitoring tools with data pipeline integration
- Social media or external APIs with rate limiting and error handling

**Data Integration:**
- API integration patterns with circuit breaker and retry logic
- Webhook implementations with signature validation and replay protection
- Message queue systems with dead letter queues and monitoring
- Event-driven architecture with event sourcing and CQRS patterns

**9. DEVELOPMENT WORKFLOW:**

**Code Organization:**
- Monorepo vs microrepo strategy with dependency management
- Component architecture patterns with clear separation of concerns
- Code reuse strategies with shared libraries and design systems
- Documentation standards with automated documentation generation

**Quality Assurance:**
- Comprehensive testing strategy (unit, integration, e2e, performance)
- Code review processes with automated checks and security scanning
- Performance testing with load testing and stress testing
- Security testing with SAST, DAST, and dependency scanning

**10. TECHNICAL DEBT & FUTURE CONSIDERATIONS:**

**Architecture Evolution:**
- Technology upgrade roadmap with migration strategies
- Scalability enhancement opportunities with performance benchmarks
- Security enhancement priorities with threat modeling updates
- Feature roadmap alignment with architectural decisions

**Maintenance Strategy:**
- Dependency management with automated updates and security patches
- Technical debt tracking with prioritization matrix
- Refactoring priorities with code quality metrics
- Documentation maintenance with automated updates

**Long-term Sustainability:**
- Team training and knowledge transfer strategies
- Code maintainability standards with complexity analysis
- Performance monitoring and optimization roadmap
- Security posture improvement with regular audits

Provide detailed, production-ready architecture that can be directly implemented by development teams. Focus on enterprise-grade solutions that scale gracefully and maintain high security and performance standards over time."""

        return prompt

# Factory function for OUT-HOMING compatibility
def create_falcon_architect() -> FalconArchitect:
    """Factory function to create EXTENSIVE FALCON architect instance"""
    return FalconArchitect()

# Test function for FALCON bird
def test_falcon_bird():
    """Test the EXTENSIVE FALCON bird with sample SPARK input"""
    falcon = create_falcon_architect()
    
    # Mock SPARK requirements using your existing format
    spark_requirements = {
        "raw_analysis": "Build a comprehensive snake game with HTML, CSS, and JavaScript featuring modern game mechanics, responsive design, and progressive web app capabilities",
        "json_data": {
            "core_objective": "Create an interactive snake game with enterprise-grade architecture",
            "in_scope": ["Game mechanics", "Score tracking", "Visual interface", "PWA features", "Responsive design"],
            "out_of_scope": ["Multiplayer features", "Backend user accounts"],
            "complexity": "moderate"
        }
    }
    
    design = falcon.design_architecture(spark_requirements)
    
    print("🧪 TESTING EXTENSIVE FALCON BIRD (SYSTEM-COMPATIBLE)")
    print(f"🦅 Stage: {design['stage']}")
    print(f"🤖 Model: {design['model']}")
    print(f"🏗️ Design Type: {design['design_type']}")
    print(f"📏 Prompt Length: {len(design['prompt'])} characters")
    print(f"🎯 Target Range: {falcon.target_chars} characters")
    print(f"🔥 Temperature: {design['temperature']}")
    print(f"📊 Max Tokens: {design['max_tokens']}")
    
    return design

if __name__ == "__main__":
    # Test EXTENSIVE FALCON bird independently
    test_falcon_bird()