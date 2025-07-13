#!/usr/bin/env python3
"""
falcon.py - EXTENSIVE FALCON Architecture Design Bird (SYSTEM-COMPATIBLE VERSION)
The comprehensive system architect with complexity-aware architecture design
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
        self.optimal_model = "meta-llama/llama-4-scout-17b-16e-instruct"
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
        """Build comprehensive architecture prompt with complexity-aware design"""
        
        prompt = f"""<thinking>
I need to design a technical architecture based on SPARK requirements, tailoring it to the project's complexity.

Requirements: {spark_text[:500]}...
Data: {requirements_data}

First, I must check the project complexity from SPARK:
- Simple apps (e.g., games, CLI tools): Use Python standard library or Pygame, no backend/database.
- Complex apps (e.g., web apps, analytics): Use appropriate Python frameworks (e.g., FastAPI, Streamlit), include backend/database as needed.

I should provide:
- For simple apps: Minimal Python-based architecture, single-file or modular Python, local execution.
- For complex apps: Full enterprise architecture with backend, database, and deployment strategy.
- Technology stack, database design, and API specs matching complexity.
- Scalability, security, and DevOps tailored to project needs.
</thinking>

Act as Falcon, a senior solution architect with 15+ years of experience designing enterprise-grade and lightweight applications.

Design the technical architecture for this system based on SPARK requirements:

**REQUIREMENTS ANALYSIS:**
{spark_text}

**ADDITIONAL CONTEXT:**
{json.dumps(requirements_data, indent=2) if requirements_data else "No additional structured data"}

Provide comprehensive architecture design in this EXACT format:

**1. PROJECT COMPLEXITY:**
[Simple or Complex, extracted from SPARK or inferred from requirements]

**2. TECHNOLOGY STACK RECOMMENDATIONS:**

**Frontend Technology:**
[For simple apps: "None" or "Pygame" for games, "CLI" for utilities; For complex apps: Streamlit/Gradio or minimal frontend]

**Backend Technology:**
[For simple apps: "Python" with standard library; For complex apps: FastAPI/Flask, authentication, and validation]

**Database Strategy:**
[For simple apps: "None" or file-based storage; For complex apps: PostgreSQL/SQLite with caching (e.g., Redis)]

**DevOps & Infrastructure:**
[For simple apps: "Local execution"; For complex apps: Docker, CI/CD, cloud deployment]

**3. SYSTEM ARCHITECTURE DIAGRAM:**

**High-Level Architecture:**
[For simple apps:]
```
[Python Script] → [Local Execution]
```
[For complex apps:]
```
[Browser/Client] ↔ [API Gateway (FastAPI)] ↔ [Backend Service] ↔ [Database]
    ↓                       ↓                       ↓                   ↓
[UI (Streamlit)]   [Authentication]       [Business Logic]      [Data Storage]
```

**Component Interactions:**
[For simple apps: Describe Python script execution flow; For complex apps: Detail authentication, data flow, and integrations]

**4. DATABASE DESIGN:**

**Entity Relationship Model:**
[For simple apps: None or simple file-based schema; For complex apps: SQL schema with tables, indexes, and relationships]

**Data Flow Architecture:**
[For simple apps: Basic data handling in Python; For complex apps: CRUD operations, validation, and optimization]

**5. API ARCHITECTURE:**

**API Design:**
[For simple apps: None or simple function-based API; For complex apps: RESTful API with endpoints, e.g., GET/POST /api/v1/resources]

**API Standards:**
[For simple apps: None or minimal; For complex apps: JSON:API, error handling, versioning, and documentation]

**6. SECURITY ARCHITECTURE:**

**Authentication & Authorization:**
[For simple apps: None or basic validation; For complex apps: JWT/OAuth, RBAC, session management]

**Data Protection:**
[For simple apps: Basic input sanitization; For complex apps: Encryption, SQL injection prevention, XSS/CSRF protection]

**Infrastructure Security:**
[For simple apps: None or minimal; For complex apps: TLS, security headers, rate limiting]

**7. SCALABILITY STRATEGY:**

**Horizontal Scaling:**
[For simple apps: None; For complex apps: Load balancing, database sharding, microservices]

**Performance Optimization:**
[For simple apps: Basic Python optimization; For complex apps: Caching, query optimization, asset compression]

**8. DEPLOYMENT ARCHITECTURE:**

**Environment Strategy:**
[For simple apps: Local Python environment; For complex apps: Docker, staging/production environments]

**CI/CD Pipeline:**
[For simple apps: Manual execution; For complex apps: GitHub Actions, automated testing, and deployment]

**9. INTEGRATION STRATEGY:**

**Third-Party Integrations:**
[For simple apps: None or minimal; For complex apps: Payment systems, email services, analytics]

**Data Integration:**
[For simple apps: None; For complex apps: API integrations, webhooks, message queues]

**10. DEVELOPMENT WORKFLOW:**

**Code Organization:**
[For simple apps: Single or few Python files; For complex apps: Modular structure, shared utilities]

**Quality Assurance:**
[For simple apps: Basic unit tests; For complex apps: Comprehensive testing, code reviews]

**11. TECHNICAL DEBT & FUTURE CONSIDERATIONS:**

**Architecture Evolution:**
[For simple apps: Minimal upgrades; For complex apps: Technology roadmap, scalability enhancements]

**Maintenance Strategy:**
[For simple apps: Basic updates; For complex apps: Dependency management, refactoring plans]

Provide detailed, production-ready architecture that matches the project’s complexity (simple or complex) as defined by SPARK. Ensure the tech stack and design align with the requirements for immediate implementation."""

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
        "raw_analysis": "Build a simple snake game in Python with basic game mechanics and CLI interface",
        "json_data": {
            "core_objective": "Create a lightweight snake game in Python",
            "in_scope": ["Game mechanics", "Score tracking", "CLI interface"],
            "out_of_scope": ["Web interface", "Multiplayer features"],
            "complexity": "simple"
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
