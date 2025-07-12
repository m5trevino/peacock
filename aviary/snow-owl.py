#!/usr/bin/env python3
"""
snow-owl.py - Blueprint Synthesizer (DeepSeek Synthesis Stage 1)
Combines SPARK and FALCON responses into unified ProjectBlueprint
"""

import os
import json
import requests
import datetime
from pathlib import Path
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()


class BlueprintSynthesizer:
    """Snow Owl - Blueprint Synthesizer for DeepSeek synthesis stage 1"""
    
    def __init__(self):
        self.stage_name = "SNOW-OWL"
        self.icon = "🦉"
        self.specialty = "Blueprint Synthesis"
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
    
    def create_blueprint(self, spark_response: str, falcon_response: str, session_id: str) -> str:
        """
        Main synthesizer method - creates unified ProjectBlueprint from SPARK and FALCON
        
        Args:
            spark_response: The raw SPARK response text
            falcon_response: The raw FALCON response text  
            session_id: Session identifier for logging
            
        Returns:
            Clean, validated JSON string for ProjectBlueprint
        """
        print(f"🦉 SNOW-OWL: Synthesizing ProjectBlueprint for session {session_id}")
        
        try:
            # Build direct-imperative prompt for DeepSeek
            prompt = self._build_synthesis_prompt(spark_response, falcon_response)
            
            # Log the prompt
            self._log_prompt(prompt, session_id)
            
            # Make API call to DeepSeek model
            response_text = self._call_synthesis_model(prompt)
            
            # Log the response
            self._log_response(response_text, session_id)
            
            # Extract and validate JSON from response
            blueprint_json = self._extract_json(response_text)
            
            print(f"✅ SNOW-OWL: ProjectBlueprint synthesis completed successfully")
            return blueprint_json
            
        except Exception as e:
            error_msg = f"SNOW-OWL synthesis failed: {str(e)}"
            print(f"❌ {error_msg}")
            
            # Log the error
            self._log_error(error_msg, session_id)
            return f'{{"error": "{error_msg}"}}'
    
    def _build_synthesis_prompt(self, spark_response: str, falcon_response: str) -> str:
        """Build direct-imperative prompt for DeepSeek (no system prompt)"""
        
        prompt = f"""You are a senior technical architect tasked with synthesizing requirements analysis and system architecture into a unified project blueprint.

TASK: Create a comprehensive ProjectBlueprint JSON by combining the SPARK requirements analysis and FALCON architecture design below.

SPARK REQUIREMENTS ANALYSIS:
{spark_response}

FALCON ARCHITECTURE DESIGN:
{falcon_response}

OUTPUT REQUIREMENTS:
1. Return ONLY valid JSON in the exact ProjectBlueprint schema format
2. Synthesize information from both reports - don't duplicate, integrate
3. Extract concrete technical decisions from FALCON
4. Extract business requirements from SPARK
5. Create actionable development phases
6. Include realistic timelines and resource estimates

EXACT JSON SCHEMA REQUIRED:
{{
  "project_name": "string",
  "description": "string", 
  "core_objective": "string",
  "business_value": "string",
  "technical_stack": {{
    "frontend": "string",
    "backend": "string", 
    "database": "string",
    "deployment": "string"
  }},
  "key_features": [
    {{
      "name": "string",
      "description": "string",
      "priority": "high|medium|low",
      "complexity": "simple|moderate|complex"
    }}
  ],
  "development_phases": [
    {{
      "phase": "string",
      "duration_weeks": "number",
      "deliverables": ["string"],
      "dependencies": ["string"]
    }}
  ],
  "quality_requirements": {{
    "performance_targets": ["string"],
    "security_requirements": ["string"],
    "testing_strategy": ["string"]
  }},
  "resource_estimates": {{
    "team_size": "number",
    "total_timeline_weeks": "number",
    "technical_complexity": "low|medium|high",
    "risk_factors": ["string"]
  }},
  "success_metrics": [
    {{
      "metric": "string",
      "target": "string",
      "measurement": "string"
    }}
  ]
}}

SYNTHESIS GUIDELINES:
- Extract project name from SPARK core objective
- Combine technical stack details from FALCON with business requirements from SPARK
- Create 3-5 key features based on SPARK in-scope items and FALCON capabilities
- Design 3-4 development phases based on FALCON architecture complexity
- Set realistic timeline estimates (most projects: 8-16 weeks)
- Include specific performance targets from both reports
- Identify concrete risk factors from technical and business analysis

Generate complete, actionable ProjectBlueprint JSON now:"""

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
        """Log the synthesis prompt to logs/{session_id}/09_synth1_blueprint_prompt.txt"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        prompt_file = log_dir / "09_synth1_blueprint_prompt.txt"
        
        with open(prompt_file, 'w', encoding='utf-8') as f:
            f.write(f"# SYNTHESIS 1 - BLUEPRINT PROMPT - {datetime.datetime.now().isoformat()}\n")
            f.write(f"# Model: {self.synthesis_model}\n")
            f.write(f"# Session: {session_id}\n")
            f.write("# " + "="*70 + "\n\n")
            f.write(prompt)
        
        print(f"📝 Logged synthesis prompt: {prompt_file}")
    
    def _log_response(self, response_text: str, session_id: str):
        """Log the raw JSON response to logs/{session_id}/10_synth1_blueprint_response.json"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        response_file = log_dir / "10_synth1_blueprint_response.json"
        
        # Create structured response data
        response_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "model": self.synthesis_model,
            "session_id": session_id,
            "stage": "SYNTHESIS_1_BLUEPRINT",
            "response_length": len(response_text),
            "raw_response": response_text,
            "metadata": {
                "synthesizer": "SNOW-OWL",
                "model_params": self.model_params,
                "synthesis_inputs": ["SPARK", "FALCON"]
            }
        }
        
        with open(response_file, 'w', encoding='utf-8') as f:
            json.dump(response_data, f, indent=2, ensure_ascii=False)
        
        print(f"💾 Logged synthesis response: {response_file}")
    
    def _log_error(self, error_msg: str, session_id: str):
        """Log errors to the session directory"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        error_file = log_dir / "synthesis1_error.log"
        
        with open(error_file, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.datetime.now().isoformat()}] {error_msg}\n")
        
        print(f"🚨 Logged error: {error_file}")


def create_blueprint_synthesizer() -> BlueprintSynthesizer:
    """Factory function to create BlueprintSynthesizer instance"""
    return BlueprintSynthesizer()


def test_blueprint_synthesizer():
    """Test the blueprint synthesizer with sample input"""
    synthesizer = create_blueprint_synthesizer()
    
    test_spark = """**1. CORE OBJECTIVE:**
Build a comprehensive task management web application with real-time collaboration features that enables teams to efficiently organize, track, and complete projects.

**2. FUNCTIONAL REQUIREMENTS:**
**Core Features (Must Have):**
- User authentication and role-based access control
- Project creation and management with team assignment
- Task creation, assignment, and tracking with status updates
- Real-time notifications and activity feeds
- File upload and attachment system for tasks"""
    
    test_falcon = """**1. TECHNOLOGY STACK RECOMMENDATIONS:**
**Frontend Technology:**
- Framework: React 18.2.0 with TypeScript for type safety
- State Management: Redux Toolkit with RTK Query for data fetching
- UI Library: Material-UI 5.x with custom design system

**Backend Technology:**
- Runtime Environment: Node.js 18.x LTS with Express.js 4.x
- Database Strategy: PostgreSQL 15.x with Redis 7.x for caching
- Authentication: JWT with refresh token rotation"""
    
    test_session = "test-session-synth1-001"
    
    print("🧪 TESTING SNOW-OWL BLUEPRINT SYNTHESIZER")
    print(f"📝 SPARK Preview: {test_spark[:100]}...")
    print(f"🏗️ FALCON Preview: {test_falcon[:100]}...")
    print(f"🎯 Session: {test_session}")
    print(f"🤖 Model: {synthesizer.synthesis_model}")
    print("="*60)
    
    response = synthesizer.create_blueprint(test_spark, test_falcon, test_session)
    
    print(f"📊 Response Length: {len(response)} characters")
    print(f"✅ Test completed for session: {test_session}")
    
    return response


if __name__ == "__main__":
    # Test blueprint synthesizer independently
    test_blueprint_synthesizer()