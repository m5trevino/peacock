#!/usr/bin/env python3
"""
great-owl.py - Build Plan Synthesizer (DeepSeek Synthesis Stage 2)
Combines EAGLE and HAWK responses into unified BuildAndTestPlan
"""

import os
import json
import requests
import datetime
from pathlib import Path
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()


class BuildPlanSynthesizer:
    """Great Owl - Build Plan Synthesizer for DeepSeek synthesis stage 2"""
    
    def __init__(self):
        self.stage_name = "GREAT-OWL"
        self.icon = "🦉"
        self.specialty = "Build Plan Synthesis"
        self.synthesis_model = "deepseek-r1-distill-llama-70b"
        
        # API Configuration - using GROQ
        self.groq_api_keys = [
            os.getenv("GROQ_API_KEY"),
            os.getenv("GROQ_API_KEY_1"),
            os.getenv("GROQ_API_KEY_2"),
            os.getenv("GROQ_API_KEY_3"),
            os.getenv("GROQ_API_KEY_4"),
            os.getenv("GROQ_API_KEY_5"),
            os.getenv("GROQ_API_KEY_6"),
            os.getenv("GROQ_API_KEY_7"),
            os.getenv("GROQ_API_KEY_8"),
            os.getenv("GROQ_API_KEY_9")
        ]
        self.groq_api_keys = [key for key in self.groq_api_keys if key]
        self.current_key_index = 0
        
        # GROQ model parameters
        self.model_params = {
            "temperature": 0.1,
            "top_p": 0.95,
            "max_tokens": 4096
        }
    
    def create_build_plan(self, eagle_response: str, hawk_response: str, session_id: str) -> str:
        """
        Main synthesizer method - creates unified BuildAndTestPlan from EAGLE and HAWK
        
        Args:
            eagle_response: The raw EAGLE response text
            hawk_response: The raw HAWK response text  
            session_id: Session identifier for logging
            
        Returns:
            Clean, validated JSON string for BuildAndTestPlan
        """
        print(f"🦉 GREAT-OWL: Synthesizing BuildAndTestPlan for session {session_id}")
        
        try:
            # Build direct-imperative prompt for DeepSeek
            prompt = self._build_synthesis_prompt(eagle_response, hawk_response)
            
            # Log the prompt
            self._log_prompt(prompt, session_id)
            
            # Make API call to synthesis model
            response_text = self._call_synthesis_model(prompt)
            
            # Log the response
            self._log_response(response_text, session_id)
            
            # Extract and validate JSON from response
            build_plan_json = self._extract_json(response_text)
            
            print(f"✅ GREAT-OWL: BuildAndTestPlan synthesis completed successfully")
            return build_plan_json
            
        except Exception as e:
            error_msg = f"GREAT-OWL synthesis failed: {str(e)}"
            print(f"❌ {error_msg}")
            
            # Log the error
            self._log_error(error_msg, session_id)
            return f'{{"error": "{error_msg}"}}'
    
    def _build_synthesis_prompt(self, eagle_response: str, hawk_response: str) -> str:
        """Build direct-imperative prompt for DeepSeek (no system prompt)"""
        
        prompt = f"""You are a senior development lead tasked with creating a comprehensive build and test plan by combining code implementation details with quality assurance requirements.

TASK: Create a detailed BuildAndTestPlan JSON by synthesizing the EAGLE implementation and HAWK quality assurance analysis below.

EAGLE CODE IMPLEMENTATION:
{eagle_response}

HAWK QUALITY ASSURANCE ANALYSIS:
{hawk_response}

OUTPUT REQUIREMENTS:
1. Return ONLY valid JSON in the exact BuildAndTestPlan schema format
2. Synthesize technical implementation details from EAGLE with QA requirements from HAWK
3. Create concrete, actionable build steps and testing procedures
4. Include specific commands, tools, and configurations
5. Design comprehensive testing strategy covering all quality aspects
6. Include deployment and production readiness checklists

EXACT JSON SCHEMA REQUIRED:
{{
  "build_configuration": {{
    "environment_setup": {{
      "node_version": "string",
      "dependencies": ["string"],
      "dev_dependencies": ["string"],
      "environment_variables": ["string"]
    }},
    "build_commands": [
      {{
        "step": "string",
        "command": "string",
        "description": "string",
        "expected_output": "string"
      }}
    ],
    "deployment_steps": [
      {{
        "phase": "string",
        "actions": ["string"],
        "verification": ["string"],
        "rollback_plan": "string"
      }}
    ]
  }},
  "testing_strategy": {{
    "unit_testing": {{
      "framework": "string",
      "coverage_target": "number",
      "test_files": ["string"],
      "critical_components": ["string"]
    }},
    "integration_testing": {{
      "test_scenarios": ["string"],
      "api_endpoints": ["string"],
      "database_tests": ["string"],
      "external_services": ["string"]
    }},
    "end_to_end_testing": {{
      "user_journeys": ["string"],
      "browser_compatibility": ["string"],
      "performance_benchmarks": ["string"],
      "accessibility_checks": ["string"]
    }}
  }},
  "quality_gates": {{
    "code_quality": {{
      "linting_rules": ["string"],
      "code_complexity_limits": "string",
      "security_scans": ["string"],
      "dependency_audits": ["string"]
    }},
    "performance_requirements": {{
      "load_testing": ["string"],
      "response_time_targets": ["string"],
      "memory_usage_limits": ["string"],
      "concurrent_user_targets": ["string"]
    }},
    "security_validation": {{
      "authentication_tests": ["string"],
      "authorization_checks": ["string"],
      "data_protection_verification": ["string"],
      "vulnerability_assessments": ["string"]
    }}
  }},
  "ci_cd_pipeline": {{
    "pipeline_stages": [
      {{
        "stage": "string",
        "triggers": ["string"],
        "actions": ["string"],
        "success_criteria": ["string"],
        "failure_handling": "string"
      }}
    ],
    "deployment_environments": [
      {{
        "environment": "string",
        "requirements": ["string"],
        "deployment_strategy": "string",
        "monitoring_setup": ["string"]
      }}
    ]
  }},
  "monitoring_and_maintenance": {{
    "health_checks": ["string"],
    "performance_monitoring": ["string"],
    "error_tracking": ["string"],
    "backup_procedures": ["string"],
    "maintenance_schedules": ["string"]
  }},
  "documentation_requirements": {{
    "technical_docs": ["string"],
    "user_documentation": ["string"],
    "api_documentation": ["string"],
    "deployment_guides": ["string"],
    "troubleshooting_guides": ["string"]
  }}
}}

SYNTHESIS GUIDELINES:
- Extract specific technologies and frameworks from EAGLE implementation
- Incorporate quality requirements and testing strategies from HAWK analysis
- Create concrete build commands based on the tech stack identified
- Design testing approach that covers all components mentioned in EAGLE
- Include security measures and performance requirements from HAWK
- Create realistic CI/CD pipeline stages based on project complexity
- Specify monitoring requirements for production deployment
- Include comprehensive documentation based on system complexity

Generate complete, actionable BuildAndTestPlan JSON now:"""

        return prompt
    
    def _call_synthesis_model(self, prompt: str) -> str:
        """Make API call to synthesis model via GROQ"""
        
        if not self.groq_api_keys:
            raise Exception("No GROQ API keys available")
        
        # Get current API key
        api_key = self.groq_api_keys[self.current_key_index % len(self.groq_api_keys)]
        
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.synthesis_model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            **self.model_params
        }
        
        try:
            print(f"🌐 Calling synthesis model: {self.synthesis_model}")
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=180
            )
            
            if response.status_code == 200:
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"]
                print(f"✅ Synthesis model response received: {len(content)} characters")
                return content
            else:
                error_msg = f"API Error {response.status_code}: {response.text}"
                print(f"❌ {error_msg}")
                
                # Try rotating to next key
                self.current_key_index += 1
                if self.current_key_index < len(self.groq_api_keys):
                    print(f"🔄 Rotating to next API key ({self.current_key_index + 1}/{len(self.groq_api_keys)})")
                    return self._call_synthesis_model(prompt)
                else:
                    raise Exception(error_msg)
                    
        except requests.exceptions.RequestException as e:
            raise Exception(f"Network error: {str(e)}")
    
    def _extract_json(self, response_text: str) -> str:
        """Extract and validate JSON from DeepSeek response"""
        
        # Look for JSON content
        start_markers = ['{', '```json\n{', '```\n{']
        end_markers = ['}', '}\n```', '}\n```\n']
        
        json_start = -1
        json_end = -1
        
        # Find JSON start
        for marker in start_markers:
            pos = response_text.find(marker)
            if pos != -1:
                json_start = pos + (len(marker) - 1) if marker != '{' else pos
                break
        
        if json_start == -1:
            raise Exception("No JSON found in DeepSeek response")
        
        # Find JSON end (look for last closing brace)
        for i in range(len(response_text) - 1, json_start, -1):
            if response_text[i] == '}':
                json_end = i + 1
                break
        
        if json_end == -1:
            raise Exception("Incomplete JSON in DeepSeek response")
        
        json_text = response_text[json_start:json_end]
        
        # Validate JSON
        try:
            parsed = json.loads(json_text)
            # Re-serialize to ensure clean formatting
            return json.dumps(parsed, indent=2, ensure_ascii=False)
        except json.JSONDecodeError as e:
            raise Exception(f"Invalid JSON from DeepSeek: {str(e)}")
    
    def _log_prompt(self, prompt: str, session_id: str):
        """Log the synthesis prompt to logs/{session_id}/11_synth2_buildplan_prompt.txt"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        prompt_file = log_dir / "11_synth2_buildplan_prompt.txt"
        
        with open(prompt_file, 'w', encoding='utf-8') as f:
            f.write(f"# SYNTHESIS 2 - BUILD PLAN PROMPT - {datetime.datetime.now().isoformat()}\n")
            f.write(f"# Model: {self.synthesis_model}\n")
            f.write(f"# Session: {session_id}\n")
            f.write("# " + "="*70 + "\n\n")
            f.write(prompt)
        
        print(f"📝 Logged synthesis prompt: {prompt_file}")
    
    def _log_response(self, response_text: str, session_id: str):
        """Log the raw JSON response to logs/{session_id}/12_synth2_buildplan_response.json"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        response_file = log_dir / "12_synth2_buildplan_response.json"
        
        # Create structured response data
        response_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "model": self.synthesis_model,
            "session_id": session_id,
            "stage": "SYNTHESIS_2_BUILDPLAN",
            "response_length": len(response_text),
            "raw_response": response_text,
            "metadata": {
                "synthesizer": "GREAT-OWL",
                "model_params": self.model_params,
                "synthesis_inputs": ["EAGLE", "HAWK"]
            }
        }
        
        with open(response_file, 'w', encoding='utf-8') as f:
            json.dump(response_data, f, indent=2, ensure_ascii=False)
        
        print(f"💾 Logged synthesis response: {response_file}")
    
    def _log_error(self, error_msg: str, session_id: str):
        """Log errors to the session directory"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        error_file = log_dir / "synthesis2_error.log"
        
        with open(error_file, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.datetime.now().isoformat()}] {error_msg}\n")
        
        print(f"🚨 Logged error: {error_file}")


def create_build_plan_synthesizer() -> BuildPlanSynthesizer:
    """Factory function to create BuildPlanSynthesizer instance"""
    return BuildPlanSynthesizer()


def test_build_plan_synthesizer():
    """Test the build plan synthesizer with sample input"""
    synthesizer = create_build_plan_synthesizer()
    
    test_eagle = """**PROJECT OVERVIEW:**
Complete enterprise task management web application with React frontend, Node.js backend, PostgreSQL database.

**COMPLETE CODE FILES:**

filename: package.json
{
  "name": "task-management-app",
  "dependencies": {
    "express": "^4.18.2",
    "react": "^18.2.0",
    "postgresql": "^3.2.1",
    "socket.io": "^4.7.2"
  }
}

filename: server.js
[Complete Express.js server with authentication, API endpoints, and WebSocket support]"""
    
    test_hawk = """**1. TESTING STRATEGY:**
**Unit Testing Plan:**
- Authentication and authorization comprehensive tests
- API endpoint testing with various scenarios
- Database integration and transaction tests

**2. SECURITY VALIDATION:**
- JWT token validation and expiration handling
- Input validation and sanitization
- HTTPS/TLS verification

**3. PERFORMANCE TESTING:**
- Concurrent user capacity (target: 500+ users)
- API response times (target: <200ms)
- Database query performance (<100ms)"""
    
    test_session = "test-session-synth2-001"
    
    print("🧪 TESTING GREAT-OWL BUILD PLAN SYNTHESIZER")
    print(f"📝 EAGLE Preview: {test_eagle[:100]}...")
    print(f"🔍 HAWK Preview: {test_hawk[:100]}...")
    print(f"🎯 Session: {test_session}")
    print(f"🤖 Model: {synthesizer.synthesis_model}")
    print("="*60)
    
    response = synthesizer.create_build_plan(test_eagle, test_hawk, test_session)
    
    print(f"📊 Response Length: {len(response)} characters")
    print(f"✅ Test completed for session: {test_session}")
    
    return response


if __name__ == "__main__":
    # Test build plan synthesizer independently
    test_build_plan_synthesizer()