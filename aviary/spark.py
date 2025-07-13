#!/usr/bin/env python3
"""
spark.py - EXTENSIVE SPARK Requirements Analysis Bird (SYSTEM-COMPATIBLE VERSION)
The comprehensive strategic analyst with complexity-aware requirements
"""

import json
import re
from typing import Dict, List, Any

class SparkAnalyst:
    """SPARK - The Strategic Requirements Analyst (EXTENSIVE VERSION - COMPATIBLE)"""
    
    def __init__(self):
        self.stage_name = "SPARK"
        self.icon = "⚡"
        self.specialty = "Comprehensive Strategic Requirements Analysis"
        self.optimal_model = "meta-llama/llama-4-scout-17b-16e-instruct"
        self.target_chars = "2500-4000"
    
    def analyze_project_request(self, user_request: str) -> Dict[str, Any]:
        """
        Main SPARK function - maintains compatibility with OUT-HOMING orchestrator
        """
        print(f"⚡ EXTENSIVE SPARK ANALYST: Generating comprehensive requirements analysis...")
        
        # Generate the EXTENSIVE SPARK analysis prompt
        spark_prompt = self._build_extensive_spark_prompt(user_request)
        
        # Package using your existing format for OUT-HOMING compatibility
        spark_analysis = {
            "stage": "SPARK",
            "prompt": spark_prompt,
            "user_request": user_request,
            "model": self.optimal_model,
            "temperature": 0.2,  # Lower for more structured analysis
            "max_tokens": 2048,  # Increased for extensive content
            "analysis_type": "comprehensive_strategic_requirements"
        }
        
        print(f"✅ EXTENSIVE SPARK prompt generated: {len(spark_prompt)} characters (Target: {self.target_chars})")
        return spark_analysis
    
    def _build_extensive_spark_prompt(self, user_request: str) -> str:
        """Build comprehensive strategic analysis prompt with complexity detection"""
        
        prompt = f"""<thinking>
I need to analyze this project comprehensively as a senior requirements analyst with 15+ years of experience.

Project Request: {user_request}

First, I must determine the project complexity:
- Simple apps: Games, CLI tools, or small utilities (e.g., "snake game", "calculator")
  - Use Python standard library or minimal libraries (e.g., Pygame for games)
  - No backend, database, or complex infrastructure
  - Minimal features, no enterprise requirements
- Complex apps: Web apps, analytics platforms, or enterprise systems (e.g., "business analytics", "task management")
  - Include appropriate frameworks (e.g., FastAPI, Streamlit)
  - Include backend, database, and infrastructure as needed
  - Full enterprise requirements (security, scalability, etc.)

Complexity keywords:
- Simple: "game", "CLI", "simple", "basic", "small", "utility"
- Complex: "web", "analytics", "dashboard", "enterprise", "platform", "management"

I should provide:
- For simple apps: Lightweight requirements with Python focus, minimal scope
- For complex apps: Full enterprise analysis with strategic value, detailed requirements
- Clear scope, stakeholder analysis, and success metrics tailored to complexity
</thinking>

Act as Spark, a senior requirements analyst with 15+ years of experience in enterprise software development and strategic business analysis.

Analyze this project request comprehensively:

**PROJECT REQUEST:** {user_request}

Determine the project complexity based on keywords and context, then provide requirements analysis in this EXACT format:

**1. PROJECT COMPLEXITY:**
[Simple or Complex, with justification based on keywords and request context]

**2. CORE OBJECTIVE:**
[One clear sentence describing the primary goal, tailored to complexity]

**3. CURRENT STATE ANALYSIS:**
[For simple apps: Brief context of user need; For complex apps: Detailed pain points, existing tools, and market context]

**4. TARGET STATE VISION:**
[For simple apps: Simple functional description; For complex apps: Detailed vision with KPIs, ROI, and competitive advantages]

**5. FUNCTIONAL REQUIREMENTS:**

**Core Features (Must Have):**
[For simple apps: 2-3 basic features with acceptance criteria; For complex apps: 4-5 detailed features with acceptance criteria]

**Secondary Features (Should Have):**
[For simple apps: 1-2 optional enhancements; For complex apps: 2-3 enhancements with justification]

**Future Features (Could Have):**
[For simple apps: 1 future idea; For complex apps: 2-3 future considerations with timelines]

**6. NON-FUNCTIONAL REQUIREMENTS:**

**Performance Requirements:**
[For simple apps: Basic performance needs (e.g., "runs smoothly on standard hardware"); For complex apps: Detailed response times, throughput, scalability]

**Security Requirements:**
[For simple apps: Minimal security (e.g., "no sensitive data exposure"); For complex apps: Authentication, data protection, compliance (e.g., GDPR)]

**Usability Requirements:**
[For simple apps: Basic usability (e.g., "intuitive controls"); For complex apps: Accessibility (WCAG), UX standards, device compatibility]

**Reliability Requirements:**
[For simple apps: Basic error handling; For complex apps: Detailed error handling, backup, and monitoring]

**7. TECHNICAL CONSTRAINTS:**
[For simple apps: Python standard library or Pygame, local execution; For complex apps: Appropriate frameworks (e.g., FastAPI, Streamlit), hosting, and integrations]

**8. STAKEHOLDER ANALYSIS:**

**Primary Users:**
[For simple apps: Single user type with basic needs; For complex apps: Multiple user types with detailed needs]

**Secondary Stakeholders:**
[For simple apps: None or minimal; For complex apps: Detailed stakeholders with concerns]

**Decision Makers:**
[For simple apps: User as decision maker; For complex apps: Business/technical decision makers]

**9. RISK ASSESSMENT:**

**Technical Risks:**
[For simple apps: 1-2 minor risks; For complex apps: Multiple risks with mitigation]

**Business Risks:**
[For simple apps: Minimal or none; For complex apps: Detailed risks with mitigation]

**Dependencies and Assumptions:**
[For simple apps: Minimal dependencies; For complex apps: Detailed dependencies and assumptions]

**10. PROJECT SCOPE:**

**In Scope (Deliverables):**
[For simple apps: 1-2 deliverables (e.g., single Python file); For complex apps: Multiple deliverables with acceptance criteria]

**Out of Scope (Exclusions):**
[For simple apps: Complex features like backend; For complex apps: Explicit exclusions with rationale]

**Scope Boundaries:**
[For simple apps: Local app boundaries; For complex apps: Integration and migration boundaries]

**11. SUCCESS CRITERIA & METRICS:**

**Launch Criteria:**
[For simple apps: Functional app; For complex apps: Measurable outcomes and quality gates]

**Post-Launch Metrics:**
[For simple apps: User satisfaction; For complex apps: User adoption, performance, ROI]

**Long-term Success Indicators:**
[For simple apps: Continued use; For complex apps: ROI, market impact, retention]

Provide thorough, strategic, and complexity-aware analysis that drives subsequent development stages. Ensure requirements match the project’s complexity (simple or complex) based on the request."""

        return prompt
    
    def _parse_spark_response(self, response_text: str) -> Dict[str, Any]:
        """Parse the LLM response and extract structured requirements"""
        
        requirements = {
            "core_objective": "",
            "current_state": "",
            "target_state": "",
            "in_scope": [],
            "out_of_scope": [],
            "json_data": {}
        }
        
        # Extract complexity
        complexity_match = re.search(r'\*\*1\. Project Complexity:\*\*\s*\n([^\n*]+)', response_text)
        if complexity_match:
            requirements["json_data"]["complexity"] = complexity_match.group(1).strip().split(',')[0].strip()
        
        # Extract core objective
        obj_match = re.search(r'\*\*2\. Core Objective:\*\*\s*\n([^\n*]+)', response_text)
        if obj_match:
            requirements["core_objective"] = obj_match.group(1).strip()
        
        # Extract current state
        current_match = re.search(r'\*\*3\. Current State Analysis:\*\*\s*\n([^\n*]+)', response_text)
        if current_match:
            requirements["current_state"] = current_match.group(1).strip()
        
        # Extract target state
        target_match = re.search(r'\*\*4\. Target State Vision:\*\*\s*\n([^\n*]+)', response_text)
        if target_match:
            requirements["target_state"] = target_match.group(1).strip()
        
        # Extract in scope items
        in_scope_section = re.search(r'\*\*Core Features \(Must Have\):\*\*\s*\n((?:- [^\n]+\n?)+)', response_text)
        if in_scope_section:
            scope_items = re.findall(r'- ([^\n]+)', in_scope_section.group(1))
            requirements["in_scope"] = [item.strip() for item in scope_items]
        
        # Extract out of scope items
        out_scope_section = re.search(r'\*\*Out of Scope \(Exclusions\):\*\*\s*\n((?:- [^\n]+\n?)+)', response_text)
        if out_scope_section:
            out_items = re.findall(r'- ([^\n]+)', out_scope_section.group(1))
            requirements["out_of_scope"] = [item.strip() for item in out_items]
        
        return requirements

# Factory function for OUT-HOMING compatibility
def create_spark_analyst() -> SparkAnalyst:
    """Factory function to create EXTENSIVE SPARK analyst instance"""
    return SparkAnalyst()

# Test function for SPARK bird
def test_spark_bird():
    """Test the EXTENSIVE SPARK bird with sample input"""
    spark = create_spark_analyst()
    
    test_request = "Build a simple snake game in Python"
    analysis = spark.analyze_project_request(test_request)
    
    print("🧪 TESTING EXTENSIVE SPARK BIRD (SYSTEM-COMPATIBLE)")
    print(f"📝 Request: {test_request}")
    print(f"⚡ Stage: {analysis['stage']}")
    print(f"🤖 Model: {analysis['model']}")
    print(f"📊 Analysis Type: {analysis['analysis_type']}")
    print(f"📏 Prompt Length: {len(analysis['prompt'])} characters")
    print(f"🎯 Target Range: {spark.target_chars} characters")
    print(f"🔥 Temperature: {analysis['temperature']}")
    print(f"📊 Max Tokens: {analysis['max_tokens']}")
    
    return analysis

if __name__ == "__main__":
    # Test EXTENSIVE SPARK bird independently
    test_spark_bird()