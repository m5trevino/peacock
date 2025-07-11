#!/usr/bin/env python3
"""
spark.py - EXTENSIVE SPARK Requirements Analysis Bird (SYSTEM-COMPATIBLE VERSION)
The comprehensive strategic analyst with your existing method patterns
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
        self.optimal_model = "llama3-8b-8192"
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
        """Build comprehensive strategic analysis prompt"""
        
        prompt = f"""<thinking>
I need to analyze this project comprehensively as a senior requirements analyst with 15+ years of experience.

Project: {user_request}

I should provide:
- Strategic business analysis with clear value proposition
- Detailed functional requirements with acceptance criteria
- Non-functional requirements (performance, security, usability)
- Technical constraints and platform considerations
- Stakeholder analysis with success criteria
- Risk assessment with mitigation strategies
- Clear scope definition with boundaries
- Success metrics and KPIs
</thinking>

Act as Spark, a senior requirements analyst with 15+ years of experience in enterprise software development and strategic business analysis.

Analyze this project request comprehensively:

**PROJECT REQUEST:** {user_request}

Provide detailed requirements analysis in this EXACT format:

**1. CORE OBJECTIVE:**
[One clear, strategic sentence describing the primary business goal and value proposition]

**2. CURRENT STATE ANALYSIS:**
- Existing pain points and inefficiencies
- Current tools/systems in use (if applicable)
- Business impact of current limitations
- Stakeholder challenges and frustrations
- Market context and competitive landscape

**3. TARGET STATE VISION:**
- Desired end state after successful implementation
- Key success metrics and measurable KPIs
- Business value proposition and ROI potential
- User experience improvements
- Competitive advantages gained

**4. FUNCTIONAL REQUIREMENTS:**

**Core Features (Must Have):**
- [Primary feature 1 with detailed acceptance criteria]
- [Primary feature 2 with detailed acceptance criteria]
- [Primary feature 3 with detailed acceptance criteria]
- [Primary feature 4 with detailed acceptance criteria]

**Secondary Features (Should Have):**
- [Enhancement 1 with business justification]
- [Enhancement 2 with business justification]
- [Enhancement 3 with business justification]

**Future Features (Could Have):**
- [Future consideration 1 with timeline estimate]
- [Future consideration 2 with timeline estimate]

**5. NON-FUNCTIONAL REQUIREMENTS:**

**Performance Requirements:**
- Response time expectations (page load, API calls)
- Throughput requirements (concurrent users, transactions)
- Scalability needs (growth projections)
- Availability targets (uptime requirements)

**Security Requirements:**
- Authentication and authorization needs
- Data protection and privacy requirements
- Compliance requirements (GDPR, HIPAA, etc.)
- Security threat model and mitigation

**Usability Requirements:**
- Accessibility standards (WCAG compliance)
- User experience standards
- Browser and device compatibility
- Internationalization needs

**Reliability Requirements:**
- Error handling and graceful degradation
- Backup and disaster recovery needs
- Data integrity requirements
- Monitoring and alerting needs

**6. TECHNICAL CONSTRAINTS:**
- Platform limitations and preferences
- Integration requirements with existing systems
- Legacy system considerations
- Budget constraints and timeline limitations
- Technology stack preferences
- Hosting and infrastructure constraints

**7. STAKEHOLDER ANALYSIS:**

**Primary Users:**
- [User type 1: needs, expectations, success criteria]
- [User type 2: needs, expectations, success criteria]

**Secondary Stakeholders:**
- [Stakeholder type 1: requirements, concerns]
- [Stakeholder type 2: requirements, concerns]

**Decision Makers:**
- [Decision maker: approval criteria, concerns]

**8. RISK ASSESSMENT:**

**Technical Risks:**
- [Risk 1: probability, impact, mitigation strategy]
- [Risk 2: probability, impact, mitigation strategy]

**Business Risks:**
- [Risk 1: probability, impact, mitigation strategy]
- [Risk 2: probability, impact, mitigation strategy]

**Dependencies and Assumptions:**
- Critical dependencies on external systems
- Key assumptions about user behavior
- Market assumptions and validations needed

**9. PROJECT SCOPE:**

**In Scope (Deliverables):**
- [Clearly defined deliverable 1 with acceptance criteria]
- [Clearly defined deliverable 2 with acceptance criteria]
- [Clearly defined deliverable 3 with acceptance criteria]

**Out of Scope (Exclusions):**
- [Explicitly excluded item 1 with rationale]
- [Explicitly excluded item 2 with rationale]
- [Future phase considerations]

**Scope Boundaries:**
- Integration boundaries
- Data migration boundaries
- User training boundaries

**10. SUCCESS CRITERIA & METRICS:**

**Launch Criteria:**
- Measurable outcomes that define project success
- Acceptance criteria for go-live decision
- Quality gates and validation checkpoints

**Post-Launch Metrics:**
- User adoption metrics
- Performance metrics
- Business impact metrics
- Customer satisfaction metrics

**Long-term Success Indicators:**
- ROI achievement timeline
- Market impact measurements
- User retention and engagement

Provide thorough, strategic, and business-focused analysis that will drive all subsequent development stages. Be comprehensive enough that developers can understand both the WHAT and the WHY behind every requirement."""

        return prompt
    
    def _parse_spark_response(self, response_text: str) -> Dict[str, Any]:
        """Parse the LLM response and extract structured requirements (if needed for compatibility)"""
        
        requirements = {
            "core_objective": "",
            "current_state": "",
            "target_state": "",
            "in_scope": [],
            "out_of_scope": [],
            "json_data": {}
        }
        
        # Extract core objective
        obj_match = re.search(r'\*\*1\. Core Objective:\*\*\s*\n([^\n*]+)', response_text)
        if obj_match:
            requirements["core_objective"] = obj_match.group(1).strip()
        
        # Extract current state
        current_match = re.search(r'\*\*2\. Current State Analysis:\*\*\s*\n([^\n*]+)', response_text)
        if current_match:
            requirements["current_state"] = current_match.group(1).strip()
        
        # Extract target state
        target_match = re.search(r'\*\*3\. Target State Vision:\*\*\s*\n([^\n*]+)', response_text)
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
    
    test_request = "Build a comprehensive enterprise task management application with real-time collaboration, advanced reporting, and mobile accessibility"
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