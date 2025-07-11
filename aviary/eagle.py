#!/usr/bin/env python3
"""
eagle.py - EXTENSIVE EAGLE Code Implementation Bird (SYSTEM-COMPATIBLE VERSION)
The comprehensive full-stack developer with your existing method patterns
"""

import json
import re
from typing import Dict, List, Any

class EagleImplementer:
    """EAGLE - The Code Implementation Specialist (EXTENSIVE VERSION - COMPATIBLE)"""
    
    def __init__(self):
        self.stage_name = "EAGLE"
        self.icon = "🦅"
        self.specialty = "Complete Code Implementation & Development"
        self.optimal_model = "llama3-8b-8192"
        self.target_chars = "6000-10000"
    
    def implement_code(self, falcon_architecture: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main EAGLE function - maintains compatibility with OUT-HOMING orchestrator
        """
        print(f"🦅 EXTENSIVE EAGLE IMPLEMENTER: Creating comprehensive code implementation...")
        
        # Extract data using your existing patterns
        architecture_text = falcon_architecture.get("raw_design", "")
        if not architecture_text:
            architecture_text = falcon_architecture.get("architecture", "")
        
        json_data = falcon_architecture.get("json_data", {})
        if not json_data:
            json_data = falcon_architecture.get("analysis", {})
        
        # Generate the EXTENSIVE EAGLE prompt
        eagle_prompt = self._build_extensive_eagle_prompt(architecture_text, json_data)
        
        # Package using your existing format for OUT-HOMING compatibility
        eagle_implementation = {
            "stage": "EAGLE",
            "prompt": eagle_prompt,
            "falcon_input": falcon_architecture,
            "model": self.optimal_model,
            "temperature": 0.1,  # Lower for more precise code
            "max_tokens": 4096,  # Increased for extensive code files
            "implementation_type": "production_ready_complete"
        }
        
        print(f"✅ EXTENSIVE EAGLE prompt generated: {len(eagle_prompt)} characters (Target: {self.target_chars})")
        return eagle_implementation
    
    def _build_extensive_eagle_prompt(self, architecture_text: str, json_data: Dict[str, Any]) -> str:
        """Build comprehensive production-ready code implementation prompt"""
        
        prompt = f"""<thinking>
I need to implement complete, working code based on this architecture design.

Architecture: {architecture_text[:500]}...
Data: {json_data}

I should provide:
- Complete file structure with all necessary files
- Production-ready code with proper error handling
- Configuration files and environment setup
- Database schemas and migrations (if needed)
- API implementations with full CRUD operations
- Frontend components with complete functionality
- Testing setup and initial test cases
- Documentation and setup instructions
- Package.json with all dependencies
- README with deployment instructions
</thinking>

Act as Eagle, a senior full-stack developer with 15+ years of experience building production applications.

Transform this architecture into complete, working code:

**ARCHITECTURE DESIGN:**
{architecture_text}

**TECHNICAL SPECIFICATIONS:**
{json.dumps(json_data, indent=2) if json_data else "No additional structured data"}

Provide complete, production-ready implementation in this EXACT format:

**PROJECT OVERVIEW:**
[Comprehensive description of the complete system based on architecture specifications]

**COMPLETE CODE FILES:**

**Configuration & Setup Files:**

filename: package.json
[Complete package.json with all dependencies, scripts, and configuration for the project]

filename: .env.example
[Complete environment configuration template with all required variables]

filename: .gitignore
[Complete gitignore file with appropriate exclusions for the technology stack]

**Backend Implementation (if applicable):**

filename: server.js
[Complete server implementation with routing, middleware, comprehensive error handling]

filename: config/database.js
[Complete database configuration and connection setup with error handling]

filename: models/[ModelName].js
[Complete data models with validation, relationships, and methods]

filename: controllers/[ControllerName].js
[Complete controllers with full CRUD operations and comprehensive error handling]

filename: routes/[RouteName].js
[Complete API routes following RESTful principles with validation]

filename: middleware/auth.js
[Complete authentication middleware with JWT/session handling and security]

filename: middleware/validation.js
[Complete input validation middleware with comprehensive error handling]

filename: utils/helpers.js
[Complete utility functions and helper methods for common operations]

**Frontend Implementation:**

filename: public/index.html
[Complete HTML with semantic structure, meta tags, responsive design, and accessibility]

filename: public/styles.css
[Complete CSS with modern styling, responsive design, animations, and cross-browser compatibility]

filename: public/script.js
[Complete JavaScript with modular structure, API integration, error handling, and user interactions]

**Additional Frontend Files (if framework needed):**

filename: src/components/[ComponentName].js
[Complete component implementations with props, state, lifecycle, and error boundaries]

filename: src/services/api.js
[Complete API service layer with error handling, retry logic, and interceptors]

filename: src/utils/constants.js
[Complete constants and configuration variables for the application]

**Testing Implementation:**

filename: tests/unit/[TestName].test.js
[Complete unit tests with comprehensive coverage of core functionality]

filename: tests/integration/[TestName].test.js
[Complete integration tests with database and API testing scenarios]

filename: tests/e2e/[TestName].spec.js
[Complete end-to-end tests with user journey testing and browser automation]

**Database Implementation (if applicable):**

filename: database/migrations/001_initial_schema.sql
[Complete database schema with proper indexes, constraints, and relationships]

filename: database/seeds/sample_data.sql
[Complete sample data for development and testing purposes]

**Documentation:**

filename: README.md
[Complete documentation with setup instructions, usage examples, and API documentation]

filename: API_DOCS.md
[Complete API documentation with all endpoints, request/response examples, and error codes]

**Development Tools:**

filename: docker-compose.yml
[Complete Docker configuration for development environment with all services]

filename: Dockerfile
[Complete Docker container configuration for production deployment]

**IMPLEMENTATION NOTES:**

**Architecture Decisions:**
- [Key architectural patterns implemented and their justifications]
- [Technology choices and detailed rationales for selections]
- [Design patterns used throughout codebase for maintainability]

**Security Implementation:**
- [Authentication and authorization implementation with token management]
- [Input validation and sanitization with security best practices]
- [Security headers and CORS configuration for protection]
- [Rate limiting and DDoS protection mechanisms]

**Performance Optimizations:**
- [Caching strategies implemented at multiple levels]
- [Database query optimizations with indexing strategies]
- [Frontend performance optimizations with lazy loading]
- [Asset optimization and compression techniques]

**Error Handling Strategy:**
- [Global error handling implementation with consistent responses]
- [Logging and monitoring setup with appropriate log levels]
- [Graceful degradation patterns for service failures]
- [User-friendly error messages with actionable guidance]

**Code Organization:**
- [File structure and naming conventions for scalability]
- [Module separation and dependency management]
- [Component reusability patterns and shared utilities]
- [Configuration management and environment handling]

**SETUP & DEPLOYMENT:**

**Development Setup:**
1. Clone repository and navigate to project directory
2. Install dependencies: npm install (or appropriate package manager)
3. Configure environment variables: cp .env.example .env
4. Initialize database (if applicable): npm run db:migrate
5. Start development server: npm run dev
6. Run tests: npm test

**Production Deployment:**
1. Build application for production: npm run build
2. Configure production environment variables securely
3. Deploy to hosting platform with specific deployment instructions
4. Set up monitoring and logging with health checks
5. Configure backup and recovery procedures with testing

**Quality Assurance:**
- All code follows established coding standards and best practices
- Comprehensive error handling implemented throughout the application
- Security best practices followed with regular security audits
- Performance optimizations applied with monitoring and alerting
- Testing coverage meets industry standards with automated testing
- Documentation is complete, accurate, and maintained regularly

Provide complete, working files that can be immediately deployed without modifications. Every file should be production-ready with proper error handling, security measures, performance optimizations, and comprehensive documentation."""

        return prompt

# Factory function for OUT-HOMING compatibility
def create_eagle_implementer() -> EagleImplementer:
    """Factory function to create EXTENSIVE EAGLE implementer instance"""
    return EagleImplementer()

# Test function for EAGLE bird
def test_eagle_bird():
    """Test the EXTENSIVE EAGLE bird with sample architecture input"""
    eagle = create_eagle_implementer()
    
    # Mock FALCON architecture using your existing format
    falcon_architecture = {
        "raw_design": "Comprehensive web application architecture with modern frontend framework, RESTful API backend, database integration, and responsive design",
        "json_data": {
            "tech_stack": {
                "frontend": "React with TypeScript, Tailwind CSS",
                "backend": "Node.js with Express framework",
                "database": "PostgreSQL with Redis caching"
            },
            "complexity": "enterprise"
        }
    }
    
    implementation = eagle.implement_code(falcon_architecture)
    
    print("🧪 TESTING EXTENSIVE EAGLE BIRD (SYSTEM-COMPATIBLE)")
    print(f"🦅 Stage: {implementation['stage']}")
    print(f"🤖 Model: {implementation['model']}")
    print(f"💻 Implementation Type: {implementation['implementation_type']}")
    print(f"📏 Prompt Length: {len(implementation['prompt'])} characters")
    print(f"🎯 Target Range: {eagle.target_chars} characters")
    print(f"🔥 Temperature: {implementation['temperature']}")
    print(f"📊 Max Tokens: {implementation['max_tokens']}")
    
    return implementation

if __name__ == "__main__":
    # Test EXTENSIVE EAGLE bird independently
    test_eagle_bird()