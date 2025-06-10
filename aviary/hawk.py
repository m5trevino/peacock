#!/usr/bin/env python3
"""
hawk.py - HAWK Quality Assurance Bird
The QA specialist who ensures code quality and creates comprehensive testing strategies
"""

import json
import re
from typing import Dict, List, Any

class HawkQASpecialist:
    """HAWK - The Quality Assurance Master"""
    
    def __init__(self):
        self.stage_name = "HAWK"
        self.icon = "🦅"
        self.specialty = "Quality Assurance & Testing Strategy"
        self.optimal_model = "gemma2-9b-it"  # QA structure specialist
    
    def analyze_implementation(self, eagle_implementation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main HAWK function - analyze code quality and create testing strategy
        """
        print(f"🦅 HAWK QA SPECIALIST: Analyzing code quality and creating test strategy...")
        
        # Extract implementation data
        implementation_text = eagle_implementation.get("raw_implementation", "")
        code_files = eagle_implementation.get("code_files", [])
        
        # Generate the HAWK QA prompt
        hawk_prompt = self._build_hawk_prompt(implementation_text, code_files)
        
        # Package the QA analysis for MCP processing
        hawk_analysis = {
            "stage": "HAWK",
            "prompt": hawk_prompt,
            "eagle_input": eagle_implementation,
            "model": self.optimal_model,
            "temperature": 0.3,
            "max_tokens": 1024,
            "analysis_type": "quality_assurance"
        }
        
        return hawk_analysis
    
    def _build_hawk_prompt(self, implementation_text: str, code_files: List[Dict[str, Any]]) -> str:
        """Build the QA analysis and testing strategy prompt"""
        
        files_summary = self._generate_files_summary(code_files)
        
        prompt = f"""<thinking>
I need to analyze the implementation from Eagle and create a comprehensive QA strategy. I should look at:
- Code quality and best practices
- Security considerations
- Performance implications
- Testing requirements
- Deployment readiness

Implementation: {implementation_text[:500]}...
Files: {files_summary}
</thinking>

Act as Hawk, a senior QA engineer. Create comprehensive QA strategy for this implementation.

Implementation Details:
{implementation_text}

Provide QA strategy in this EXACT format:

**1. Test Cases:**
- Functional tests for core features
- Edge cases and error scenarios
- Integration test requirements

**2. Security Validation:**
- Authentication/authorization checks
- Input validation requirements
- Data protection measures

**3. Performance Considerations:**
- Load testing requirements
- Scalability checkpoints
- Resource optimization

**4. Error Handling Scenarios:**
- Network failure handling
- Data corruption recovery
- User error management

**5. Production Readiness Checklist:**
- Deployment requirements
- Monitoring setup
- Backup strategies

Then provide the structured data as JSON:
```json
{{
    "test_coverage": 85,
    "security_score": 9,
    "performance_rating": "good",
    "production_ready": true,
    "confidence_score": 8
}}
```

Be specific and actionable for each area."""
        
        return prompt
    
    def _generate_files_summary(self, code_files: List[Dict[str, Any]]) -> str:
        """Generate a summary of code files for the prompt"""
        if not code_files:
            return "No code files provided"
        
        summary_parts = []
        for file_data in code_files:
            summary_parts.append(f"{file_data['filename']} ({file_data['language']}, {file_data['lines']} lines)")
        
        return ", ".join(summary_parts)
    
    def validate_hawk_response(self, response_text: str) -> Dict[str, Any]:
        """Validate that HAWK response contains comprehensive QA analysis"""
        
        validation_result = {
            "valid": False,
            "has_test_cases": False,
            "has_security": False,
            "has_performance": False,
            "has_error_handling": False,
            "has_production_checklist": False,
            "has_json": False,
            "character_count": len(response_text),
            "quality_score": 0
        }
        
        # Check for test cases
        if "1. Test Cases:" in response_text:
            validation_result["has_test_cases"] = True
            validation_result["quality_score"] += 2
        
        # Check for security validation
        if "2. Security Validation:" in response_text:
            validation_result["has_security"] = True
            validation_result["quality_score"] += 2
        
        # Check for performance considerations
        if "3. Performance Considerations:" in response_text:
            validation_result["has_performance"] = True
            validation_result["quality_score"] += 2
        
        # Check for error handling
        if "4. Error Handling Scenarios:" in response_text:
            validation_result["has_error_handling"] = True
            validation_result["quality_score"] += 1
        
        # Check for production readiness
        if "5. Production Readiness Checklist:" in response_text:
            validation_result["has_production_checklist"] = True
            validation_result["quality_score"] += 2
        
        # Check for JSON data
        json_pattern = r'```json\s*\n(.*?)\n```'
        json_match = re.search(json_pattern, response_text, re.DOTALL)
        if json_match:
            try:
                json.loads(json_match.group(1))
                validation_result["has_json"] = True
                validation_result["quality_score"] += 2
            except json.JSONDecodeError:
                pass
        
        # Determine if valid
        validation_result["valid"] = (
            validation_result["has_test_cases"] and 
            validation_result["has_security"] and
            validation_result["has_performance"] and
            validation_result["character_count"] > 400
        )
        
        return validation_result
    
    def extract_qa_data(self, response_text: str) -> Dict[str, Any]:
        """Extract structured QA data from HAWK response"""
        
        qa_analysis = {
            "test_cases": [],
            "security_validation": [],
            "performance_considerations": [],
            "error_handling": [],
            "production_checklist": [],
            "json_data": {},
            "raw_analysis": response_text
        }
        
        # Extract test cases
        test_section = re.search(r'\*\*1\. Test Cases:\*\*\s*\n((?:- [^\n]+\n?)+)', response_text)
        if test_section:
            tests = re.findall(r'- ([^\n]+)', test_section.group(1))
            qa_analysis["test_cases"] = [test.strip() for test in tests]
        
        # Extract security validation
        security_section = re.search(r'\*\*2\. Security Validation:\*\*\s*\n((?:- [^\n]+\n?)+)', response_text)
        if security_section:
            security_items = re.findall(r'- ([^\n]+)', security_section.group(1))
            qa_analysis["security_validation"] = [item.strip() for item in security_items]
        
        # Extract performance considerations
        perf_section = re.search(r'\*\*3\. Performance Considerations:\*\*\s*\n((?:- [^\n]+\n?)+)', response_text)
        if perf_section:
            perf_items = re.findall(r'- ([^\n]+)', perf_section.group(1))
            qa_analysis["performance_considerations"] = [item.strip() for item in perf_items]
        
        # Extract error handling
        error_section = re.search(r'\*\*4\. Error Handling Scenarios:\*\*\s*\n((?:- [^\n]+\n?)+)', response_text)
        if error_section:
            error_items = re.findall(r'- ([^\n]+)', error_section.group(1))
            qa_analysis["error_handling"] = [item.strip() for item in error_items]
        
        # Extract production checklist
        prod_section = re.search(r'\*\*5\. Production Readiness Checklist:\*\*\s*\n((?:- [^\n]+\n?)+)', response_text)
        if prod_section:
            prod_items = re.findall(r'- ([^\n]+)', prod_section.group(1))
            qa_analysis["production_checklist"] = [item.strip() for item in prod_items]
        
        # Extract JSON data
        json_pattern = r'```json\s*\n(.*?)\n```'
        json_match = re.search(json_pattern, response_text, re.DOTALL)
        if json_match:
            try:
                qa_analysis["json_data"] = json.loads(json_match.group(1))
            except json.JSONDecodeError:
                qa_analysis["json_data"] = {}
        
        return qa_analysis
    
    def generate_test_suite(self, qa_data: Dict[str, Any], code_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate automated test suite based on QA analysis"""
        
        test_suite = {
            "unit_tests": [],
            "integration_tests": [],
            "e2e_tests": [],
            "performance_tests": [],
            "security_tests": []
        }
        
        # Generate unit tests based on code files
        for file_data in code_files:
            if file_data["language"] == "javascript":
                test_suite["unit_tests"].extend(
                    self._generate_js_unit_tests(file_data)
                )
            elif file_data["language"] == "python":
                test_suite["unit_tests"].extend(
                    self._generate_python_unit_tests(file_data)
                )
        
        # Generate integration tests
        if len(code_files) > 1:
            test_suite["integration_tests"] = [
                "Test component communication",
                "Test data flow between modules",
                "Test API integration points"
            ]
        
        # Generate E2E tests for web applications
        if any(file_data["language"] == "html" for file_data in code_files):
            test_suite["e2e_tests"] = [
                "Test complete user workflows",
                "Test cross-browser compatibility",
                "Test responsive design on different devices"
            ]
        
        # Generate performance tests
        test_suite["performance_tests"] = [
            "Load testing with simulated users",
            "Memory usage profiling",
            "Response time benchmarking"
        ]
        
        # Generate security tests
        test_suite["security_tests"] = qa_data.get("security_validation", [])
        
        return test_suite
    
    def _generate_js_unit_tests(self, file_data: Dict[str, Any]) -> List[str]:
        """Generate JavaScript unit test suggestions"""
        return [
            f"Test {file_data['filename']} function exports",
            f"Test {file_data['filename']} error handling",
            f"Test {file_data['filename']} input validation"
        ]
    
    def _generate_python_unit_tests(self, file_data: Dict[str, Any]) -> List[str]:
        """Generate Python unit test suggestions"""
        return [
            f"Test {file_data['filename']} class methods",
            f"Test {file_data['filename']} exception handling",
            f"Test {file_data['filename']} edge cases"
        ]
    
    def calculate_quality_metrics(self, qa_data: Dict[str, Any], code_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall quality metrics for the implementation"""
        
        metrics = {
            "overall_score": 0,
            "test_coverage_estimate": 0,
            "security_rating": "unknown",
            "maintainability_score": 0,
            "performance_rating": "unknown",
            "production_readiness": False
        }
        
        # Calculate based on QA analysis completeness
        json_data = qa_data.get("json_data", {})
        
        if "test_coverage" in json_data:
            metrics["test_coverage_estimate"] = json_data["test_coverage"]
        
        if "security_score" in json_data:
            score = json_data["security_score"]
            if score >= 8:
                metrics["security_rating"] = "excellent"
            elif score >= 6:
                metrics["security_rating"] = "good"
            elif score >= 4:
                metrics["security_rating"] = "fair"
            else:
                metrics["security_rating"] = "poor"
        
        if "performance_rating" in json_data:
            metrics["performance_rating"] = json_data["performance_rating"]
        
        if "production_ready" in json_data:
            metrics["production_readiness"] = json_data["production_ready"]
        
        # Calculate maintainability based on code structure
        total_lines = sum(file_data["lines"] for file_data in code_files)
        file_count = len(code_files)
        
        if file_count > 0:
            avg_lines_per_file = total_lines / file_count
            if avg_lines_per_file < 100:
                metrics["maintainability_score"] = 9
            elif avg_lines_per_file < 200:
                metrics["maintainability_score"] = 7
            elif avg_lines_per_file < 300:
                metrics["maintainability_score"] = 5
            else:
                metrics["maintainability_score"] = 3
        
        # Calculate overall score
        scores = [
            metrics["test_coverage_estimate"] / 10,  # Convert to 0-10 scale
            json_data.get("security_score", 5),
            metrics["maintainability_score"],
            8 if metrics["performance_rating"] == "excellent" else 
            6 if metrics["performance_rating"] == "good" else 4
        ]
        
        metrics["overall_score"] = sum(scores) / len(scores)
        
        return metrics

# Factory function for HAWK bird
def create_hawk_qa_specialist() -> HawkQASpecialist:
    """Factory function to create HAWK QA specialist instance"""
    return HawkQASpecialist()

# Test function for HAWK bird
def test_hawk_bird():
    """Test the HAWK bird with sample EAGLE input"""
    hawk = create_hawk_qa_specialist()
    
    # Mock EAGLE implementation
    eagle_implementation = {
        "raw_implementation": """
IMPLEMENTATION OVERVIEW:
Complete snake game with HTML5 canvas, CSS styling, and JavaScript game logic.

CODE FILES:
- index.html (50 lines)
- styles.css (75 lines) 
- script.js (150 lines)

IMPLEMENTATION NOTES:
- Used HTML5 Canvas for game rendering
- Implemented collision detection
- Added score tracking system
        """,
        "code_files": [
            {"filename": "index.html", "language": "html", "lines": 50, "size": 1200},
            {"filename": "styles.css", "language": "css", "lines": 75, "size": 1800},
            {"filename": "script.js", "language": "javascript", "lines": 150, "size": 4500}
        ]
    }
    
    analysis = hawk.analyze_implementation(eagle_implementation)
    
    print("🧪 TESTING HAWK BIRD")
    print(f"🦅 Stage: {analysis['stage']}")
    print(f"🤖 Model: {analysis['model']}")
    print(f"🔍 Analysis Type: {analysis['analysis_type']}")
    print(f"📏 Prompt Length: {len(analysis['prompt'])} characters")
    
    return analysis

if __name__ == "__main__":
    # Test HAWK bird independently
    test_hawk_bird()