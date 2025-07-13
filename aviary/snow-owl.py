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
    
    def __init__(self, broadcaster=None):
        self.stage_name = "SNOW-OWL"
        self.icon = "🦉"
        self.specialty = "Blueprint Synthesis"
        self.synthesis_model = "deepseek-r1-distill-llama-70b"
        self.groq_api_keys = [key for key in [
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
        ] if key]
        self.current_key_index = 0
        self.model_params = {
            "temperature": 0.1,
            "top_p": 0.95,
            "max_tokens": 131072,
            "response_format": {"type": "json_object"}
        }
        self.broadcaster = broadcaster
    
    def create_blueprint(self, spark_response: str, falcon_response: str, session_id: str) -> str:
        print(f"🦉 SNOW-OWL: Synthesizing ProjectBlueprint for session {session_id}")
        try:
            prompt = self._build_synthesis_prompt(spark_response, falcon_response)
            self._log_prompt(prompt, session_id)
            response_text = self._call_synthesis_model(prompt)
            self._log_response(response_text, session_id)
            blueprint_json = self._extract_json(response_text)
            if self.broadcaster:
                char_count = len(blueprint_json)
                self.broadcaster.send({"stage": "SYNTHESIS_1", "status": "COMPLETED", "char_count": char_count})
            print(f"✅ SNOW-OWL: ProjectBlueprint synthesis completed successfully")
            return blueprint_json
        except Exception as e:
            error_msg = f"SNOW-OWL synthesis failed: {str(e)}"
            print(f"❌ {error_msg}")
            self._log_error(error_msg, session_id)
            return f'{{"error": "{error_msg}"}}'
    
    def _build_synthesis_prompt(self, spark_response: str, falcon_response: str) -> str:
        prompt = f"""You are a senior technical architect tasked with synthesizing requirements analysis and system architecture into a unified project blueprint.

TASK: Create a comprehensive ProjectBlueprint JSON from SPARK and FALCON inputs below. Provide detailed, thorough content in each section to ensure complete project coverage.

SPARK REQUIREMENTS:
{spark_response}

FALCON ARCHITECTURE:
{falcon_response}

OUTPUT REQUIREMENTS:
- Return detailed, comprehensive JSON following the ProjectBlueprint schema.
- Include ALL relevant SPARK requirements and FALCON technical decisions with full explanations.
- Provide thorough descriptions, multiple phases, detailed features, and comprehensive planning.
- Target 3000+ characters for complete project coverage.
- For simple apps, use Python standard library. For complex apps, include frameworks (e.g., Flask, Docker) only if essential.

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
    "deployment": "Local"
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

Generate complete, actionable ProjectBlueprint JSON now. Ensure detailed, comprehensive content in ALL sections - aim for 3000+ characters total with thorough descriptions, multiple development phases, detailed features with full explanations, comprehensive quality requirements, and complete success metrics."""
        return prompt
    
    def _call_synthesis_model(self, prompt: str) -> str:
        if not self.groq_api_keys:
            raise Exception("No GROQ API keys available")
        api_key = self.groq_api_keys[self.current_key_index % len(self.groq_api_keys)]
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.synthesis_model,
            "messages": [{"role": "user", "content": prompt}],
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
                self.current_key_index = (self.current_key_index + 1) % len(self.groq_api_keys)
                return content
            else:
                raise Exception(f"API Error {response.status_code}: {response.text}")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Network error: {str(e)}")
    
    def _extract_json(self, response_text: str) -> str:
        start_markers = ['{', '```json\n{', '```\n{']
        end_markers = ['}', '}\n```', '}\n```\n']
        json_start = -1
        json_end = -1
        for marker in start_markers:
            pos = response_text.find(marker)
            if pos != -1:
                json_start = pos + (len(marker) - 1) if marker != '{' else pos
                break
        if json_start == -1:
            raise Exception("No JSON found in DeepSeek response")
        for i in range(len(response_text) - 1, json_start, -1):
            if response_text[i] == '}':
                json_end = i + 1
                break
        if json_end == -1:
            raise Exception("Incomplete JSON in DeepSeek response")
        json_text = response_text[json_start:json_end]
        try:
            parsed = json.loads(json_text)
            return json.dumps(parsed, indent=2, ensure_ascii=False)
        except json.JSONDecodeError as e:
            raise Exception(f"Invalid JSON from DeepSeek: {str(e)}")
    
    def _log_prompt(self, prompt: str, session_id: str):
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
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        response_file = log_dir / "10_synth1_blueprint_response.json"
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
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        error_file = log_dir / "synthesis1_error.log"
        with open(error_file, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.datetime.now().isoformat()}] {error_msg}\n")
        print(f"🚨 Logged error: {error_file}")

def create_blueprint_synthesizer(broadcaster=None) -> BlueprintSynthesizer:
    return BlueprintSynthesizer(broadcaster=broadcaster)

def summarize_spark(response: str) -> str:
    lines = response.split('\n')
    summary = []
    for line in lines[:10]:
        if line.startswith('**') or 'filename:' in line:
            summary.append(line)
    return '\n'.join(summary)[:1000]

def summarize_falcon(response: str) -> str:
    lines = response.split('\n')
    summary = []
    for line in lines[:10]:
        if line.startswith('**'):
            summary.append(line)
    return '\n'.join(summary)[:1000]