#!/usr/bin/env python3
"""
great-owl.py - EXTENSIVE GREAT-OWL Synthesis Orchestrator (SYSTEM-COMPATIBLE VERSION)
The comprehensive synthesizer that integrates all stages with complexity-aware blueprint generation
"""

import json
from typing import Dict, List, Any
import requests
import re

class GreatOwlSynthesizer:
    """GREAT-OWL - The Ultimate Synthesis Orchestrator (EXTENSIVE VERSION - COMPATIBLE)"""
    
    def __init__(self, broadcaster=None):
        self.stage_name = "GREAT-OWL"
        self.icon = "🦉"
        self.specialty = "Ultimate Solution Synthesis & Integration"
        self.optimal_model = "deepseek-r1-distill-llama-70b"
        self.target_chars = "6000-9000"
        self.broadcaster = broadcaster
    
    def create_build_plan(self, eagle_response: str, hawk_response: str, session_id: str) -> str:
        try:
            prior_stages = {
                "eagle": {"raw_implementation": eagle_response},
                "hawk": {"raw_strategy": hawk_response}
            }
            result = self.synthesize_final_blueprint(prior_stages)
            json_result = json.dumps(result, indent=2, ensure_ascii=False)
            print(f"🦉 GREAT-OWL JSON OUTPUT: {json_result[:1000]}...")  # Log first 1000 chars for debugging
            if self.broadcaster:
                char_count = len(json_result)
                self.broadcaster.send({"stage": "SYNTHESIS_2", "status": "COMPLETED", "char_count": char_count})
            return json_result
        except Exception as e:
            error_msg = f"🦉 GREAT-OWL ERROR: Failed to create build plan: {str(e)}"
            print(error_msg)
            if self.broadcaster:
                self.broadcaster.send({"stage": "SYNTHESIS_2", "status": "FAILED", "error": str(e)})
            return json.dumps({"error": error_msg})
    
    def synthesize_final_blueprint(self, prior_stages: Dict[str, Any]) -> Dict[str, Any]:
        print(f"🦉 EXTENSIVE GREAT-OWL SYNTHESIZER: Generating ultimate solution blueprint...")
        spark_text = prior_stages.get("spark", {}).get("raw_analysis", "")
        falcon_text = prior_stages.get("falcon", {}).get("raw_design", "")
        eagle_text = prior_stages.get("eagle", {}).get("raw_implementation", "")
        hawk_text = prior_stages.get("hawk", {}).get("raw_strategy", "")
        json_data = prior_stages.get("json_data", {}) or prior_stages.get("analysis", {})
        great_owl_prompt = self._build_extensive_great_owl_prompt(spark_text, falcon_text, eagle_text, hawk_text, json_data)
        
        # Call DeepSeek API (mocked for safety; replace with actual API call)
        try:
            blueprint_content = self._call_deepseek_api(great_owl_prompt, eagle_text, hawk_text, json_data)
        except Exception as e:
            print(f"🦉 API ERROR: {str(e)}")
            blueprint_content = "API call failed, using fallback blueprint."
        
        print(f"✅ EXTENSIVE GREAT-OWL prompt generated: {len(great_owl_prompt)} characters")
        return {
            "stage": "GREAT-OWL",
            "build_plan": blueprint_content,  # Structured blueprint from API
            "prior_inputs": prior_stages,
            "model": self.optimal_model,
            "temperature": 0.3,
            "max_tokens": 6000,
            "blueprint_type": "ultimate_solution_synthesis"
        }
    
    def _call_deepseek_api(self, prompt: str, eagle_text: str, hawk_text: str, json_data: Dict[str, Any]) -> str:
        # Mock API call (replace with actual DeepSeek API integration)
        # Truncate prompt to ~24,000 chars (~6,000 tokens, assuming 4 chars/token)
        if len(prompt) > 24000:
            prompt = prompt[:24000] + "\n[TRUNCATED FOR TOKEN LIMIT]"
        
        # Dynamic mock response based on Eagle, Hawk, and SnowOwl inputs
        complexity = json_data.get("resource_estimates", {}).get("technical_complexity", "simple").capitalize()
        core_objective = json_data.get("core_objective", "Build a functional application")
        features = json_data.get("key_features", [])
        feature_list = [f"- {f['name']}: {f['description']}" for f in features[:3 if complexity == "Simple" else 5]]
        test_strategy = re.search(r'Test Strategy:\s*(.*?)(?:\n|$)', hawk_text, re.DOTALL)
        test_strategy = test_strategy.group(1).strip() if test_strategy else "Unit tests with unittest"
        tech_stack = json_data.get("technical_stack", {})
        frontend = tech_stack.get("frontend", "Python")
        backend = tech_stack.get("backend", "None")
        database = tech_stack.get("database", "None")
        
        # Use raw string to avoid f-string backslash issues
        mock_response = r"""
**1. PROJECT COMPLEXITY:**
{}

**2. CONSOLIDATED REQUIREMENTS:**

**Core Objective:**
{}

**Functional Requirements:**
{}

**Non-Functional Requirements:**
{}

**3. FINAL ARCHITECTURE:**

**Technology Stack:**
- {}

**System Diagram:**
{}

**4. IMPLEMENTATION BLUEPRINT:**

**Code Structure:**
{}

**Key Files:**

**filename: requirements.txt**
```
{}
```

**filename: main.py**
```python
{}
```

**filename: models.py**
```python
{}
```

**5. QA & TESTING PLAN:**

**Test Strategy:**
- {}

**Test Files:**

**filename: tests/test_main.py**
```python
import {}
{}
```

**6. DEPLOYMENT PLAN:**

**Setup Instructions:**
{}

**Deployment Strategy:**
{}

**7. SUCCESS CRITERIA:**

**Launch Criteria:**
{}

**Post-Launch Metrics:**
{}

**8. PROJECT TIMELINE:**

**Development Phases:**
- {}

**Milestones:**
{}

**9. RISK MITIGATION:**

**Technical Risks:**
{}

**Mitigation Strategies:**
{}

**10. DOCUMENTATION:**

**filename: README.md**
```
# {}
{}
## Setup
1. Install Python 3.8+
2. Run `pip install -r requirements.txt`
3. {}
```
""".format(
            complexity,
            core_objective,
            '\n'.join(feature_list) if feature_list else "- Implement core application logic",
            "Basic performance and usability" if complexity == "Simple" else "Scalability, security, reliability",
            f"{frontend}{', ' + backend if backend != 'None' else ''}{', ' + database if database != 'None' else ''}",
            "[Python Script] → [Local Execution]" if complexity == "Simple" else (
                "[Browser/Client] ↔ [API Gateway (FastAPI)] ↔ [Backend Service] ↔ [Database]\n"
                "    ↓                       ↓                       ↓                   ↓\n"
                "[UI (Streamlit)]   [Authentication]       [Business Logic]      [Data Storage]"
            ),
            "Single file: `main.py`" if complexity == "Simple" else "Modular: main.py, models.py, routes.py",
            "pygame==2.1.2" if frontend == "Pygame" else (
                "fastapi==0.104.1\nuvicorn==0.24.0\nsqlalchemy==2.0.23\npsycopg2-binary==2.9.9" if database != "None" else
                "fastapi==0.104.1\nuvicorn==0.24.0"
            ),
            "# Core application logic" if complexity == "Simple" else "# FastAPI app initialization\n" + eagle_text[:500] + "..." if eagle_text else "# Implementation from Eagle",
            "# Not required for simple apps" if complexity == "Simple" else "# Database models and schemas",
            test_strategy,
            "unittest" if complexity == "Simple" else "pytest",
            hawk_text[:500] + "..." if hawk_text else "# Test cases from Hawk",
            "Install Python 3.8+\nRun `pip install -r requirements.txt`" if complexity == "Simple" else "Install Docker\nSet up PostgreSQL",
            "Run locally with `python main.py`" if complexity == "Simple" else "CI/CD pipeline, cloud hosting",
            "Functional application" if complexity == "Simple" else "Functionality, performance, security",
            "User satisfaction" if complexity == "Simple" else "Adoption, performance, ROI",
            f"{json_data.get('resource_estimates', {}).get('total_timeline_weeks', '1-2')} weeks",
            "Code complete, tests pass" if complexity == "Simple" else "Prototype, beta, production",
            "Minimal risks" if complexity == "Simple" else "Dependency issues, scalability risks",
            "Basic validation" if complexity == "Simple" else "Redundancy, testing, monitoring",
            json_data.get("project_name", core_objective),
            "A simple Python application" if complexity == "Simple" else "A scalable web application",
            "Run `python main.py`" if complexity == "Simple" else "Set up Docker and run `docker-compose up`"
        )
        return mock_response
    
    def _build_extensive_great_owl_prompt(self, spark_text: str, falcon_text: str, eagle_text: str, hawk_text: str, json_data: Dict[str, Any]) -> str:
        prompt = f"""Act as Great-Owl, a senior solutions architect with 20+ years of experience integrating complex software solutions.

Synthesize a final project blueprint from these inputs:

**SPARK REQUIREMENTS:**
{spark_text[:5000] if spark_text else "No spark requirements provided"}

**FALCON ARCHITECTURE:**
{falcon_text[:5000] if falcon_text else "No falcon architecture provided"}

**EAGLE IMPLEMENTATION:**
{eagle_text[:5000] if eagle_text else "No eagle implementation provided"}

**HAWK QA STRATEGY:**
{hawk_text[:5000] if hawk_text else "No hawk QA strategy provided"}

**TECHNICAL SPECIFICATIONS:**
{json.dumps(json_data, indent=2)[:5000] if json_data else "No additional structured data"}

Provide a unified, production-ready blueprint in this EXACT format:

**1. PROJECT COMPLEXITY:**
[Simple or Complex, extracted from prior stages or inferred]

**2. CONSOLIDATED REQUIREMENTS:**

**Core Objective:**
[Restate SPARK’s objective, refined for clarity]

**Functional Requirements:**
[For simple apps: 2-3 core features; For complex apps: 4-5 features with acceptance criteria]

**Non-Functional Requirements:**
[For simple apps: Basic performance/usability; For complex apps: Scalability, security, reliability]

**3. FINAL ARCHITECTURE:**

**Technology Stack:**
[For simple apps: Python, optional Pygame; For complex apps: FastAPI/Streamlit, SQLAlchemy, PostgreSQL]

**System Diagram:**
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

**4. IMPLEMENTATION BLUEPRINT:**

**Code Structure:**
[For simple apps: 1-2 Python files; For complex apps: Modular structure with main.py, models.py, routes.py]

**Key Files:**

**filename: requirements.txt**
```
[Minimal dependencies for simple apps; Full dependencies for complex apps]
```

**filename: main.py**
```python
[Main entry point; simple apps: core logic; complex apps: app initialization]
```

**filename: [module_name].py**
```python
[Additional modules for complex apps; omitted for simple apps unless needed]
```

**5. QA & TESTING PLAN:**

**Test Strategy:**
[For simple apps: 3-5 unit tests with unittest; For complex apps: Unit, integration, API tests with pytest]

**Test Files:**

**filename: tests/test_main.py**
```python
[Unit tests for main.py; simple apps: basic tests; complex apps: comprehensive tests]
```

**6. DEPLOYMENT PLAN:**

**Setup Instructions:**
[For simple apps: Local Python setup; For complex apps: Docker, cloud deployment]

**Deployment Strategy:**
[For simple apps: Run locally; For complex apps: CI/CD pipeline, cloud hosting]

**7. SUCCESS CRITERIA:**

**Launch Criteria:**
[For simple apps: Functional app; For complex apps: Functionality, performance, security]

**Post-Launch Metrics:**
[For simple apps: User satisfaction; For complex apps: Adoption, performance, ROI]

**8. PROJECT TIMELINE:**

**Development Phases:**
[For simple apps: 1-2 weeks; For complex apps: 4-8 weeks with milestones]

**Milestones:**
[For simple apps: Code complete, tests pass; For complex apps: Prototype, beta, production]

**9. RISK MITIGATION:**

**Technical Risks:**
[For simple apps: Minimal risks; For complex apps: Dependency issues, scalability risks]

**Mitigation Strategies:**
[For simple apps: Basic validation; For complex apps: Redundancy, testing, monitoring]

**10. DOCUMENTATION:**

**filename: README.md**
[Simple apps: Basic setup/run instructions; Complex apps: Detailed setup, usage, deployment]
"""
        return prompt

def create_great_owl_synthesizer(broadcaster=None) -> GreatOwlSynthesizer:
    return GreatOwlSynthesizer(broadcaster=broadcaster)

def test_great_owl_bird():
    great_owl = create_great_owl_synthesizer()
    prior_stages = {
        "spark": {"raw_analysis": "Simple application with basic functionality"},
        "falcon": {"raw_design": "Python-based architecture, no backend"},
        "eagle": {"raw_implementation": "def main():\n    print('Hello World')"},
        "hawk": {"raw_strategy": "Test Strategy: Basic unit tests with unittest"},
        "json_data": {"complexity": "simple"}
    }
    blueprint = great_owl.synthesize_final_blueprint(prior_stages)
    print("🧪 TESTING EXTENSIVE GREAT-OWL BIRD (SYSTEM-COMPATIBLE)")
    print(f"🦉 Stage: {blueprint['stage']}")
    print(f"🤖 Model: {blueprint['model']}")
    print(f"📘 Blueprint Type: {blueprint['blueprint_type']}")
    print(f"🔥 Temperature: {blueprint['temperature']}")
    print(f"📊 Max Tokens: {blueprint['max_tokens']}")
    return blueprint

if __name__ == "__main__":
    test_great_owl_bird()