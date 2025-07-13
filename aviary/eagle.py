#!/usr/bin/env python3
"""
eagle.py - EXTENSIVE EAGLE Code Implementation Bird (SYSTEM-COMPATIBLE VERSION)
The comprehensive full-stack developer with complexity-aware code generation
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
        self.optimal_model = "meta-llama/llama-4-maverick-17b-128e-instruct"
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
        """Build comprehensive production-ready code implementation prompt with complexity awareness"""
        
        prompt = f"""<thinking>
I need to implement complete, working Python code based on this FALCON architecture design.

Architecture: {architecture_text[:500]}...
Data: {json_data}

First, I must determine the project complexity from FALCON:
- Simple apps (e.g., games, CLI tools): Single or few Python files, use standard library or Pygame, no backend/database.
- Complex apps (e.g., web apps, analytics): Modular Python structure with FastAPI/Streamlit, include database if specified.

I should provide:
- For simple apps: Minimal Python code (1-2 files), basic error handling, no external dependencies unless essential (e.g., Pygame for games).
- For complex apps: Full Python application with modular structure, FastAPI/Streamlit, SQLAlchemy if database needed, comprehensive error handling.
- Requirements.txt for all dependencies.
- Setup instructions for Python environment.
</thinking>

Act as Eagle, a senior full-stack Python developer with 15+ years of experience building production applications.

Transform this architecture into complete, working Python code:

**ARCHITECTURE DESIGN:**
{architecture_text}

**TECHNICAL SPECIFICATIONS:**
{json.dumps(json_data, indent=2) if json_data else "No additional structured data"}

Provide complete, production-ready Python implementation in this EXACT format:

**PROJECT OVERVIEW:**
[Brief description of the Python application, tailored to complexity]

**COMPLETE PYTHON FILES:**

**filename: requirements.txt**
```
[Python dependencies with versions; none or minimal (e.g., pygame) for simple apps; include FastAPI, Streamlit, SQLAlchemy, etc., for complex apps]
```

**filename: main.py**
```python
[Complete main entry point; for simple apps: core logic; for complex apps: app initialization and routing]
```

**filename: [module_name].py**
```python
[Additional Python modules for complex apps; e.g., models.py, routes.py, utils.py; omitted for simple apps unless needed]
```

**Configuration & Setup Files:**

**filename: .env.example**
[For simple apps: None or minimal variables; For complex apps: Environment variables for API/database]

**filename: .gitignore**
```
[Standard Python .gitignore; e.g., __pycache__/, venv/, .env]
```

**Testing Implementation:**

**filename: tests/test_[module].py**
```python
[Basic unit tests for simple apps using unittest; Comprehensive tests for complex apps covering all components]
```

**Documentation:**

**filename: README.md**
[Simple setup/run instructions for simple apps; Detailed setup, run, and deployment instructions for complex apps]

**IMPLEMENTATION NOTES:**

**Architecture Decisions:**
[For simple apps: Simple Python structure justification; For complex apps: Modular design, framework choices]

**Security Implementation:**
[For simple apps: Basic input validation; For complex apps: Authentication, input sanitization, secure configuration]

**Performance Optimizations:**
[For simple apps: Basic Python efficiency; For complex apps: Caching, query optimization, async handling]

**Error Handling Strategy:**
[For simple apps: Basic try-except blocks; For complex apps: Comprehensive error handling, logging]

**Code Organization:**
[For simple apps: Single file or minimal modules; For complex apps: Modular structure with clear separation]

**SETUP & DEPLOYMENT:**

**Development Setup:**
1. Clone repository
2. Create virtual environment: python -m venv venv
3. Activate virtual environment: source venv/bin/activate (Linux/Mac) or venv\Scripts\activate (Windows)
4. Install dependencies: pip install -r requirements.txt
5. Run application: python main.py

**Production Deployment:**
[For simple apps: Local execution; For complex apps: Docker deployment, cloud hosting instructions]

**Quality Assurance:**
- Code follows PEP 8 standards
- Comprehensive error handling implemented
- Tests cover critical functionality
- Documentation is complete and accurate

Provide complete, working Python files that can be immediately run or deployed. Ensure code matches the project’s complexity (simple or complex) as defined by FALCON."""

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
        "raw_design": "Simple Python-based snake game with Pygame, no backend or database",
        "json_data": {
            "tech_stack": {
                "frontend": "Pygame",
                "backend": "None",
                "database": "None"
            },
            "complexity": "simple"
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
