#!/usr/bin/env python3
"""
peacock.py - Final Code Generator (QWEN Execution Stage)
Takes ProjectBlueprint and BuildAndTestPlan to generate final code
"""

import os
import json
import requests
import datetime
from pathlib import Path
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()


class CodeGenerator:
    """Peacock - Final Code Generator using QWEN for execution stage"""
    
    def __init__(self):
        self.stage_name = "PEACOCK"
        self.icon = "🦚"
        self.specialty = "Final Code Generation"
        self.qwen_model = "qwen/qwen3-32b"
        
        # API Configuration - Use GROQ for QWEN
        self.groq_api_keys = [
            os.getenv("GROQ_API_KEY"),
            os.getenv("GROQ_API_KEY_1"),
            os.getenv("GROQ_API_KEY_3"),
            os.getenv("GROQ_API_KEY_4"),
            os.getenv("GROQ_API_KEY_6"),
            os.getenv("GROQ_API_KEY_7"),
            os.getenv("GROQ_API_KEY_8"),
            os.getenv("GROQ_API_KEY_9"),
            os.getenv("GROQ_API_KEY_10"),
            os.getenv("GROQ_API_KEY_11")
        ]
        self.groq_api_keys = [key for key in self.groq_api_keys if key]
        self.current_key_index = 0
        
        # QWEN model parameters (API compatible only)
        self.model_params = {
            "temperature": 0.7,
            "top_p": 0.8,
            "max_tokens": 32768,
            "stream": False
        }
    
    def _strip_thinking_blocks(self, content: str) -> str:
        """Remove <think>...</think> blocks from QWEN response"""
        import re
        # Remove thinking blocks (handles both single and multiline)
        cleaned = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL)
        # Clean up extra whitespace
        cleaned = re.sub(r'\n\s*\n', '\n\n', cleaned.strip())
        return cleaned
    
    def generate_code(self, project_blueprint: str, build_plan: str, session_id: str) -> str:
        """
        Main code generator method - creates final code from synthesis outputs
        
        Args:
            project_blueprint: The ProjectBlueprint JSON string
            build_plan: The BuildAndTestPlan JSON string
            session_id: Session identifier for logging
            
        Returns:
            Final raw code response
        """
        print(f"🦚 PEACOCK: Generating final code for session {session_id}")
        
        try:
            # Build execution order prompt for QWEN
            prompt = self._build_execution_prompt(project_blueprint, build_plan)
            
            # Log the prompt
            self._log_prompt(prompt, session_id)
            
            # Make API call to QWEN model
            response_text = self._call_qwen_model(prompt)
            
            # Log the response
            self._log_response(response_text, session_id)
            
            print(f"✅ PEACOCK: Final code generation completed successfully")
            return response_text
            
        except Exception as e:
            error_msg = f"PEACOCK code generation failed: {str(e)}"
            print(f"❌ {error_msg}")
            
            # Log the error
            self._log_error(error_msg, session_id)
            return f"# CODE GENERATION FAILED\n{error_msg}"
    
    def _build_execution_prompt(self, project_blueprint: str, build_plan: str) -> str:
        """Build airtight execution order prompt for QWEN (no system prompt)"""
        
        prompt = f"""/no_think

You are the final code execution engine. Generate complete, production-ready code based on the comprehensive project specifications below.

EXECUTION ORDER: Generate complete application code following the exact specifications.

PROJECT BLUEPRINT:
{project_blueprint}

BUILD AND TEST PLAN:
{build_plan}

EXECUTION REQUIREMENTS:
1. Generate ALL files needed for a complete, working application
2. Include EVERY component specified in the blueprints
3. Use the EXACT technology stack specified
4. Implement ALL features and requirements listed
5. Include comprehensive error handling and validation
6. Follow the build configuration and testing requirements
7. Generate production-ready, deployable code
8. Include all configuration files, dependencies, and setup

OUTPUT FORMAT:
Provide complete files in this exact format:

**PROJECT: [Project Name]**

**FILE STRUCTURE:**
```
[Show complete directory structure]
```

**COMPLETE CODE FILES:**

**filename: package.json**
```json
[Complete package.json with all dependencies and scripts]
```

**filename: [filename]**
```[language]
[Complete file content]
```

[Continue for ALL files needed]

**SETUP INSTRUCTIONS:**
1. [Step-by-step setup commands]
2. [Installation instructions]
3. [Build and run commands]
4. [Testing commands]

**DEPLOYMENT GUIDE:**
[Complete deployment instructions with specific commands for the technology stack used]

CRITICAL EXECUTION RULES:
- Generate EVERY file mentioned in the blueprints
- Use EXACT technology versions specified
- Implement ALL security measures required
- Include ALL testing frameworks and configurations
- Follow the EXACT build process outlined
- Ensure complete functionality as specified
- Make it production-ready and deployable immediately

Execute complete code generation now. Generate ALL files for a fully working application:"""

        return prompt
    
    def _strip_thinking_blocks(self, content: str) -> str:
        """Remove <think>...</think> blocks from QWEN response"""
        import re
        # Remove thinking blocks (handles both single and multiline)
        cleaned = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL)
        # Clean up extra whitespace
        cleaned = re.sub(r'\n\s*\n', '\n\n', cleaned.strip())
        return cleaned
    
    def _call_qwen_model(self, prompt: str) -> str:
        """Make API call to QWEN model via Groq"""
        
        if not self.groq_api_keys:
            raise Exception("No GROQ API keys available for QWEN")
        
        # Get current API key
        api_key = self.groq_api_keys[self.current_key_index % len(self.groq_api_keys)]
        
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.qwen_model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            **self.model_params
        }
        
        try:
            print(f"🌐 Calling QWEN model: {self.qwen_model}")
            print(f"🎯 Parameters: temp={self.model_params['temperature']}, top_p={self.model_params['top_p']}, max_tokens={self.model_params['max_tokens']}")
            print(f"🚫 Thinking mode: disabled (non-thinking mode)")
            
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=300  # Extended timeout for large code generation
            )
            
            if response.status_code == 200:
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"]
                # Strip thinking blocks for clean code generation
                cleaned_content = self._strip_thinking_blocks(content)
                print(f"✅ QWEN model response received: {len(content)} characters (cleaned: {len(cleaned_content)})")
                return cleaned_content
            else:
                error_msg = f"QWEN API Error {response.status_code}: {response.text}"
                print(f"❌ {error_msg}")
                
                # Try rotating to next key
                self.current_key_index += 1
                if self.current_key_index < len(self.groq_api_keys):
                    print(f"🔄 Rotating to next API key ({self.current_key_index + 1}/{len(self.groq_api_keys)})")
                    return self._call_qwen_model(prompt)
                else:
                    raise Exception(error_msg)
                    
        except requests.exceptions.RequestException as e:
            raise Exception(f"QWEN network error: {str(e)}")
    
    def _log_prompt(self, prompt: str, session_id: str):
        """Log the code generation prompt to logs/{session_id}/13_codegen_prompt.txt"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        prompt_file = log_dir / "13_codegen_prompt.txt"
        
        with open(prompt_file, 'w', encoding='utf-8') as f:
            f.write(f"# FINAL CODE GENERATION PROMPT - {datetime.datetime.now().isoformat()}\n")
            f.write(f"# Model: {self.qwen_model}\n")
            f.write(f"# Session: {session_id}\n")
            f.write(f"# Temperature: {self.model_params['temperature']}\n")
            f.write(f"# Top-P: {self.model_params['top_p']}\n")
            f.write(f"# Max Tokens: {self.model_params['max_tokens']}\n")
            f.write(f"# Thinking Mode: API Default (Groq non-thinking)\n")
            f.write("# " + "="*70 + "\n\n")
            f.write(prompt)
        
        print(f"📝 Logged code generation prompt: {prompt_file}")
    
    def _log_response(self, response_text: str, session_id: str):
        """Log the raw response to logs/{session_id}/14_codegen_response.json"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        response_file = log_dir / "14_codegen_response.json"
        
        # Create structured response data
        response_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "model": self.qwen_model,
            "session_id": session_id,
            "stage": "FINAL_CODE_GENERATION",
            "response_length": len(response_text),
            "raw_response": response_text,
            "metadata": {
                "code_generator": "PEACOCK",
                "model_params": self.model_params,
                "api_key_index": self.current_key_index,
                "generation_inputs": ["ProjectBlueprint", "BuildAndTestPlan"]
            }
        }
        
        with open(response_file, 'w', encoding='utf-8') as f:
            json.dump(response_data, f, indent=2, ensure_ascii=False)
        
        print(f"💾 Logged code generation response: {response_file}")
    
    def _log_error(self, error_msg: str, session_id: str):
        """Log errors to the session directory"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        error_file = log_dir / "codegen_error.log"
        
        with open(error_file, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.datetime.now().isoformat()}] {error_msg}\n")
        
        print(f"🚨 Logged error: {error_file}")


def create_code_generator() -> CodeGenerator:
    """Factory function to create CodeGenerator instance"""
    return CodeGenerator()


def test_code_generator():
    """Test the code generator with sample input"""
    generator = create_code_generator()
    
    test_blueprint = """{
  "project_name": "TaskManager Pro",
  "description": "Enterprise task management with real-time collaboration",
  "technical_stack": {
    "frontend": "React 18.2.0 with TypeScript",
    "backend": "Node.js 18.x with Express.js",
    "database": "PostgreSQL 15.x with Redis caching",
    "deployment": "Docker with CI/CD pipeline"
  },
  "key_features": [
    {
      "name": "User Authentication",
      "description": "JWT-based auth with role management",
      "priority": "high",
      "complexity": "moderate"
    }
  ]
}"""
    
    test_build_plan = """{
  "build_configuration": {
    "environment_setup": {
      "node_version": "18.x",
      "dependencies": ["express", "react", "typescript"],
      "dev_dependencies": ["jest", "@types/node"]
    }
  },
  "testing_strategy": {
    "unit_testing": {
      "framework": "Jest",
      "coverage_target": 85
    }
  }
}"""
    
    test_session = "test-session-codegen-001"
    
    print("🧪 TESTING PEACOCK CODE GENERATOR")
    print(f"📝 Blueprint Preview: {test_blueprint[:100]}...")
    print(f"🔧 Build Plan Preview: {test_build_plan[:100]}...")
    print(f"🎯 Session: {test_session}")
    print(f"🤖 Model: {generator.qwen_model}")
    print("="*60)
    
    response = generator.generate_code(test_blueprint, test_build_plan, test_session)
    
    print(f"📊 Response Length: {len(response)} characters")
    print(f"✅ Test completed for session: {test_session}")
    
    return response


if __name__ == "__main__":
    # Test code generator independently
    test_code_generator()