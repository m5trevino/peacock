#!/usr/bin/env python3
"""
hawk.py - EXTENSIVE HAWK QA & Testing Bird (SYSTEM-COMPATIBLE VERSION)
The comprehensive quality assurance specialist with complexity-aware testing strategies
"""

import json
import re
from typing import Dict, List, Any

class HawkTester:
    """HAWK - The Quality Assurance & Testing Specialist (EXTENSIVE VERSION - COMPATIBLE)"""
    
    def __init__(self):
        self.stage_name = "HAWK"
        self.icon = "🦅"
        self.specialty = "Comprehensive QA and Testing Strategy"
        self.optimal_model = "meta-llama/llama-4-scout-17b-16e-instruct"
        self.target_chars = "3000-5000"
    
    def develop_qa_strategy(self, eagle_implementation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main HAWK function - maintains compatibility with OUT-HOMING orchestrator
        """
        print(f"🦅 EXTENSIVE HAWK TESTER: Generating comprehensive QA and testing strategy...")
        
        # Extract data using your existing patterns
        implementation_text = eagle_implementation.get("raw_implementation", "")
        if not implementation_text:
            implementation_text = eagle_implementation.get("implementation", "")
        
        json_data = eagle_implementation.get("json_data", {})
        if not json_data:
            json_data = eagle_implementation.get("analysis", {})
        
        # Generate the EXTENSIVE HAWK prompt
        hawk_prompt = self._build_extensive_hawk_prompt(implementation_text, json_data)
        
        # Package using your existing format for OUT-HOMING compatibility
        hawk_strategy = {
            "stage": "HAWK",
            "prompt": hawk_prompt,
            "eagle_input": eagle_implementation,
            "model": self.optimal_model,
            "temperature": 0.2,  # Lower for structured QA plans
            "max_tokens": 2048,  # Increased for detailed test plans
            "qa_type": "comprehensive_quality_assurance"
        }
        
        print(f"✅ EXTENSIVE HAWK prompt generated: {len(hawk_prompt)} characters (Target: {self.target_chars})")
        return hawk_strategy
    
    def _build_extensive_hawk_prompt(self, implementation_text: str, json_data: Dict[str, Any]) -> str:
        """Build comprehensive QA and testing strategy prompt with complexity awareness"""
        
        prompt = f"""<thinking>
I need to develop a QA and testing strategy based on the EAGLE implementation, tailoring it to the project's complexity.

Implementation: {implementation_text[:500]}...
Data: {json_data}

First, I must determine the project complexity from EAGLE/FALCON:
- Simple apps (e.g., games, CLI tools): Basic unit tests using unittest, focus on core functionality.
- Complex apps (e.g., web apps, analytics): Comprehensive test suite (unit, integration, API, performance), use pytest, coverage reports.

I should provide:
- For simple apps: 3-5 unit tests for core features, minimal coverage (~70%), basic edge cases.
- For complex apps: Full test suite with unit, integration, API tests, 90%+ coverage, security/performance testing.
- Test plan, setup instructions, and coverage goals tailored to complexity.
</thinking>

Act as Hawk, a senior QA engineer with 15+ years of experience in software testing for enterprise and lightweight applications.

Develop a comprehensive QA and testing strategy for this implementation:

**IMPLEMENTATION DETAILS:**
{implementation_text}

**TECHNICAL SPECIFICATIONS:**
{json.dumps(json_data, indent=2) if json_data else "No additional structured data"}

Provide a detailed QA and testing strategy in this EXACT format:

**1. PROJECT COMPLEXITY:**
[Simple or Complex, extracted from EAGLE/FALCON or inferred from implementation]

**2. TESTING OBJECTIVES:**
[For simple apps: Ensure core functionality works; For complex apps: Ensure functionality, performance, security, and scalability]

**3. TEST STRATEGY:**

**Unit Testing:**
[For simple apps: 3-5 unittest tests for core logic; For complex apps: pytest-based unit tests for all modules, mocks for external dependencies]

**Integration Testing:**
[For simple apps: None or minimal; For complex apps: Test component interactions, database connectivity, API integrations]

**API Testing:**
[For simple apps: None; For complex apps: Test all RESTful endpoints, status codes, payloads using tools like requests]

**Performance Testing:**
[For simple apps: None or basic runtime checks; For complex apps: Load/stress tests using locust, benchmark response times]

**Security Testing:**
[For simple apps: Basic input validation checks; For complex apps: OWASP-based tests, SQL injection, XSS prevention]

**4. TEST COVERAGE GOALS:**
[For simple apps: ~70% coverage, focus on critical paths; For complex apps: 90%+ coverage, including edge cases]

**5. TEST IMPLEMENTATION:**

**filename: tests/test_main.py**
```python
[Unit tests for main.py; simple apps: 3-5 tests; complex apps: comprehensive tests with pytest]
```

**filename: tests/test_[module].py**
```python
[For complex apps: Additional test files for modules (e.g., test_routes.py, test_models.py); omitted for simple apps]
```

**6. TEST SETUP & EXECUTION:**

**Setup Instructions:**
1. Install test dependencies: pip install pytest pytest-cov [other dependencies]
2. Run tests: pytest --cov=app tests/
3. Generate coverage report: pytest-cov

**Execution Plan:**
[For simple apps: Run unit tests locally; For complex apps: Run full test suite in CI/CD, include coverage reports]

**7. QUALITY METRICS:**

**Pass/Fail Criteria:**
[For simple apps: All core functionality tests pass; For complex apps: 90% test pass rate, no critical bugs]

**Coverage Metrics:**
[For simple apps: ~70% line coverage; For complex apps: 90%+ line/branch coverage]

**Defect Tracking:**
[For simple apps: Manual tracking; For complex apps: Integration with tools like Jira, defect severity classification]

**8. RISK-BASED TESTING:**

**High-Risk Areas:**
[For simple apps: Core logic errors; For complex apps: API failures, database issues, security vulnerabilities]

**Mitigation Strategies:**
[For simple apps: Focused unit tests; For complex apps: Prioritize high-risk tests, automated regression]

**9. AUTOMATION STRATEGY:**

**Test Automation Tools:**
[For simple apps: unittest; For complex apps: pytest, pytest-cov, locust for performance]

**CI/CD Integration:**
[For simple apps: Optional manual tests; For complex apps: GitHub Actions pipeline for automated testing]

**10. QA DOCUMENTATION:**

**Test Plan:**
[For simple apps: Brief plan for core tests; For complex apps: Detailed plan with test cases, schedules]

**Test Reports:**
[For simple apps: Basic pass/fail summary; For complex apps: Detailed reports with coverage, defects]

Provide a comprehensive, production-ready QA and testing strategy that matches the project’s complexity (simple or complex) as defined by EAGLE/FALCON. Ensure tests are Python-based, executable, and aligned with implementation requirements."""

        return prompt

# Factory function for OUT-HOMING compatibility
def create_hawk_tester() -> HawkTester:
    """Factory function to create EXTENSIVE HAWK tester instance"""
    return HawkTester()

# Test function for HAWK bird
def test_hawk_bird():
    """Test the EXTENSIVE HAWK bird with sample EAGLE input"""
    hawk = create_hawk_tester()
    
    # Mock EAGLE implementation using your existing format
    eagle_implementation = {
        "raw_implementation": "Simple Python snake game with Pygame, single file, no backend",
        "json_data": {
            "tech_stack": {
                "frontend": "Pygame",
                "backend": "None",
                "database": "None"
            },
            "complexity": "simple"
        }
    }
    
    strategy = hawk.develop_qa_strategy(eagle_implementation)
    
    print("🧪 TESTING EXTENSIVE HAWK BIRD (SYSTEM-COMPATIBLE)")
    print(f"🦅 Stage: {strategy['stage']}")
    print(f"🤖 Model: {strategy['model']}")
    print(f"🧪 QA Type: {strategy['qa_type']}")
    print(f"📏 Prompt Length: {len(strategy['prompt'])} characters")
    print(f"🎯 Target Range: {hawk.target_chars} characters")
    print(f"🔥 Temperature: {strategy['temperature']}")
    print(f"📊 Max Tokens: {strategy['max_tokens']}")
    
    return strategy

if __name__ == "__main__":
    # Test EXTENSIVE HAWK bird independently
    test_hawk_bird()
