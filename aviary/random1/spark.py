#!/usr/bin/env python3
"""
spark.py - SPARK Requirements Analysis Bird
The strategic analyst who breaks down user requests into clear, actionable requirements
"""

import json
import re
from typing import Dict, List, Any

class SparkAnalyst:
    """SPARK - The Requirements Whisperer"""
    
    def __init__(self):
        self.stage_name = "SPARK"
        self.icon = "⚡"
        self.specialty = "Strategic Requirements Analysis"
        self.optimal_model = "llama3-8b-8192"  # Speed for requirements
    
    def analyze_project_request(self, user_request: str) -> Dict[str, Any]:
        """
        Generate requirements analysis prompt based on user request.
        MCP will handle the actual LLM call.
        """
        print(f"⚡ SPARK ANALYST: Generating requirements analysis prompt...")
        
        # Generate the SPARK analysis prompt
        spark_prompt = self._build_spark_prompt(user_request)
        
        # Package the analysis for MCP processing
        spark_analysis = {
            "stage": "SPARK",
            "prompt": spark_prompt,
            "user_request": user_request,
            "model": self.optimal_model,
            "temperature": 0.3,
            "max_tokens": 1024,
            "analysis_type": "requirements_extraction"
        }
        
        print(f"✅ SPARK prompt generated: {len(spark_prompt)} characters")
        return spark_analysis
    
    def _build_spark_prompt(self, user_request: str) -> str:
        """Build the strategic SPARK analysis prompt"""
        
        return f"""<thinking>
The user wants me to analyze this project idea strategically. I need to break this down into clear, actionable components.

Project: {user_request}

I should provide:
1. Core objective - what's the main goal?
2. Current state - what problems does this solve?
3. Target state - what's the desired outcome?
4. In scope - what features are included?
5. Out of scope - what's not included?
</thinking>

Act as Spark, a strategic requirements analyst. Analyze this project idea:

Project: {user_request}

Provide analysis in this EXACT format:

**1. Core Objective:**
[One clear sentence describing the main goal]

**2. Current State:**
[Current situation/problems this solves]

**3. Target State:**
[Desired end state after implementation]

**4. In Scope:**
- [Feature 1]
- [Feature 2] 
- [Feature 3]

**5. Out of Scope:**
- [What's NOT included]
- [Future considerations]

Then provide the structured data as JSON:
```json
{{
    "core_objective": "string",
    "current_state": "string",
    "target_state": "string", 
    "in_scope": ["list"],
    "out_of_scope": ["list"],
    "confidence_score": 8
}}
"""
        
        return prompt
    
    def validate_spark_response(self, response_text: str) -> Dict[str, Any]:
        """Validate that SPARK response contains required elements"""
        
        validation_result = {
            "valid": False,
            "has_objective": False,
            "has_scope": False,
            "has_json": False,
            "character_count": len(response_text),
            "quality_score": 0
        }
        
        # Check for core sections
        if "Core Objective:" in response_text:
            validation_result["has_objective"] = True
            validation_result["quality_score"] += 2
        
        if "In Scope:" in response_text and "Out of Scope:" in response_text:
            validation_result["has_scope"] = True
            validation_result["quality_score"] += 2
        
        # Check for JSON data
        json_pattern = r'```json\s*\n(.*?)\n```'
        json_match = re.search(json_pattern, response_text, re.DOTALL)
        if json_match:
            try:
                json.loads(json_match.group(1))
                validation_result["has_json"] = True
                validation_result["quality_score"] += 3
            except json.JSONDecodeError:
                pass
        
        # Determine if valid
        validation_result["valid"] = (
            validation_result["has_objective"] and 
            validation_result["has_scope"] and
            validation_result["character_count"] > 200
        )
        
        return validation_result
    
    def extract_requirements_data(self, response_text: str) -> Dict[str, Any]:
        """Extract structured requirements data from SPARK response"""
        
        requirements = {
            "core_objective": "",
            "current_state": "",
            "target_state": "",
            "in_scope": [],
            "out_of_scope": [],
            "json_data": {},
            "raw_analysis": response_text
        }
        
        # Extract core objective
        obj_match = re.search(r'\*\*1\. Core Objective:\*\*\s*\n([^\n*]+)', response_text)
        if obj_match:
            requirements["core_objective"] = obj_match.group(1).strip()
        
        # Extract current state
        current_match = re.search(r'\*\*2\. Current State:\*\*\s*\n([^\n*]+)', response_text)
        if current_match:
            requirements["current_state"] = current_match.group(1).strip()
        
        # Extract target state
        target_match = re.search(r'\*\*3\. Target State:\*\*\s*\n([^\n*]+)', response_text)
        if target_match:
            requirements["target_state"] = target_match.group(1).strip()
        
        # Extract in scope items
        in_scope_section = re.search(r'\*\*4\. In Scope:\*\*\s*\n((?:- [^\n]+\n?)+)', response_text)
        if in_scope_section:
            scope_items = re.findall(r'- ([^\n]+)', in_scope_section.group(1))
            requirements["in_scope"] = [item.strip() for item in scope_items]
        
        # Extract out of scope items
        out_scope_section = re.search(r'\*\*5\. Out of Scope:\*\*\s*\n((?:- [^\n]+\n?)+)', response_text)
        if out_scope_section:
            out_items = re.findall(r'- ([^\n]+)', out_scope_section.group(1))
            requirements["out_of_scope"] = [item.strip() for item in out_items]
        
        # Extract JSON data
        json_pattern = r'```json\s*\n(.*?)\n```'
        json_match = re.search(json_pattern, response_text, re.DOTALL)
        if json_match:
            try:
                requirements["json_data"] = json.loads(json_match.group(1))
            except json.JSONDecodeError:
                requirements["json_data"] = {}
        
        return requirements

# Factory function for SPARK bird
def create_spark_analyst() -> SparkAnalyst:
    """Factory function to create SPARK analyst instance"""
    return SparkAnalyst()

# Test function for SPARK bird
def test_spark_bird():
    """Test the SPARK bird with sample input"""
    spark = create_spark_analyst()
    
    test_request = "Build a snake game with HTML, CSS, and JavaScript"
    analysis = spark.analyze_project_request(test_request)
    
    print("🧪 TESTING SPARK BIRD")
    print(f"📝 Request: {test_request}")
    print(f"⚡ Stage: {analysis['stage']}")
    print(f"🤖 Model: {analysis['model']}")
    print(f"📊 Analysis Type: {analysis['analysis_type']}")
    print(f"📏 Prompt Length: {len(analysis['prompt'])} characters")
    
    return analysis

if __name__ == "__main__":
    # Test SPARK bird independently
    test_spark_bird()