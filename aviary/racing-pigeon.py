#!/usr/bin/env python3
"""
racing-pigeon.py - FALCON API Handler 
Replaces FALCON orchestration logic from out_homing.py for SCOUT model calls
"""

import os
import json
import requests
import datetime
from pathlib import Path
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()

from falcon import FalconArchitect


class FalconHandler:
    """FALCON API Handler - Manages SCOUT model calls for FALCON architecture"""
    
    def __init__(self, broadcaster=None):
        self.stage_name = "RACING-PIGEON"
        self.icon = "🏎️"
        self.specialty = "FALCON API Communication"
        self.scout_model = "meta-llama/llama-4-scout-17b-16e-instruct"
        
        # API Configuration
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
        
        # Standard model parameters
        self.model_params = {
            "temperature": 0.3,
            "top_p": 0.8,
            "max_tokens": 2048
        }
        
        # Initialize FALCON architect
        self.falcon_architect = FalconArchitect()
        self.broadcaster = broadcaster
    
    def get_architecture(self, spark_response: str, session_id: str) -> str:
        """
        Main handler method - gets FALCON architecture from SCOUT model
        
        Args:
            spark_response: The raw SPARK response text
            session_id: Session identifier for logging
            
        Returns:
            Raw LLM response text
        """
        print(f"🏎️ RACING-PIGEON: Handling FALCON architecture for session {session_id}")
        
        try:
            # Prepare spark requirements in expected format
            spark_requirements = {
                "raw_analysis": spark_response,
                "analysis": spark_response,
                "json_data": {}
            }
            
            # Get prompt data from FalconArchitect
            falcon_data = self.falcon_architect.design_architecture(spark_requirements)
            prompt = falcon_data["prompt"]
            
            # Log the prompt
            self._log_prompt(prompt, session_id)
            
            # Make API call to SCOUT model
            response_text = self._call_scout_model(prompt)
            
            # Log the response
            self._log_response(response_text, session_id)
            
            print(f"✅ RACING-PIGEON: FALCON architecture completed successfully")
            return response_text
            
        except Exception as e:
            error_msg = f"RACING-PIGEON API call failed: {str(e)}"
            print(f"❌ {error_msg}")
            
            # Log the error
            self._log_error(error_msg, session_id)
            return f"# API CALL FAILED\n{error_msg}"
    
    def _call_scout_model(self, prompt: str) -> str:
        """Make API call to SCOUT model via Groq"""
        
        if not self.groq_api_keys:
            raise Exception("No GROQ API keys available")
        
        # Get current API key
        api_key = self.groq_api_keys[self.current_key_index % len(self.groq_api_keys)]
        
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.scout_model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            **self.model_params
        }
        
        try:
            print(f"🌐 Calling SCOUT model: {self.scout_model}")
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=120
            )
            
            if response.status_code == 200:
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"]
                if self.broadcaster:
                    char_count = len(content)
                    self.broadcaster.send({"stage": "FALCON", "status": "COMPLETED", "char_count": char_count})
                print(f"✅ SCOUT model response received: {len(content)} characters")
                
                # Rotate to next API key for deck-of-cards style rotation
                self.current_key_index = (self.current_key_index + 1) % len(self.groq_api_keys)
                
                return content
            else:
                error_msg = f"API Error {response.status_code}: {response.text}"
                print(f"❌ {error_msg}")
                
                # Try rotating to next key
                self.current_key_index += 1
                if self.current_key_index < len(self.groq_api_keys):
                    print(f"🔄 Rotating to next API key ({self.current_key_index + 1}/{len(self.groq_api_keys)})")
                    return self._call_scout_model(prompt)
                else:
                    raise Exception(error_msg)
                    
        except requests.exceptions.RequestException as e:
            raise Exception(f"Network error: {str(e)}")
    
    def _log_prompt(self, prompt: str, session_id: str):
        """Log the FALCON prompt to logs/{session_id}/03_falcon_prompt.txt"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        prompt_file = log_dir / "03_falcon_prompt.txt"
        
        with open(prompt_file, 'w', encoding='utf-8') as f:
            f.write(f"# FALCON PROMPT - {datetime.datetime.now().isoformat()}\n")
            f.write(f"# Model: {self.scout_model}\n")
            f.write(f"# Session: {session_id}\n")
            f.write("# " + "="*70 + "\n\n")
            f.write(prompt)
        
        print(f"📝 Logged FALCON prompt: {prompt_file}")
    
    def _log_response(self, response_text: str, session_id: str):
        """Log the raw JSON response to logs/{session_id}/04_falcon_response.json"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        response_file = log_dir / "04_falcon_response.json"
        
        # Create structured response data
        response_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "model": self.scout_model,
            "session_id": session_id,
            "stage": "FALCON",
            "response_length": len(response_text),
            "raw_response": response_text,
            "metadata": {
                "api_handler": "RACING-PIGEON",
                "model_params": self.model_params,
                "api_key_index": self.current_key_index
            }
        }
        
        with open(response_file, 'w', encoding='utf-8') as f:
            json.dump(response_data, f, indent=2, ensure_ascii=False)
        
        print(f"💾 Logged FALCON response: {response_file}")
    
    def _log_error(self, error_msg: str, session_id: str):
        """Log errors to the session directory"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        error_file = log_dir / "falcon_error.log"
        
        with open(error_file, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.datetime.now().isoformat()}] {error_msg}\n")
        
        print(f"🚨 Logged error: {error_file}")


def create_falcon_handler(broadcaster=None) -> FalconHandler:
    """Factory function to create FalconHandler instance"""
    return FalconHandler(broadcaster=broadcaster)


def test_falcon_handler():
    """Test the FALCON handler with sample input"""
    handler = create_falcon_handler()
    
    test_spark_response = """**1. CORE OBJECTIVE:**
Build a comprehensive task management web application with real-time collaboration features that enables teams to efficiently organize, track, and complete projects with enterprise-grade performance and security.

**2. CURRENT STATE ANALYSIS:**
- Teams struggling with fragmented task management across multiple tools
- Lack of real-time collaboration causing communication delays
- No centralized visibility into project progress and bottlenecks
- Manual status updates creating administrative overhead
- Poor integration between project planning and execution tools

**3. TARGET STATE VISION:**
- Unified platform for all task and project management activities
- Real-time collaboration with instant updates and notifications
- Comprehensive dashboard with project analytics and reporting
- Automated workflow management with customizable business rules
- Seamless integration with existing development and business tools"""
    
    test_session = "test-session-falcon-001"
    
    print("🧪 TESTING RACING-PIGEON FALCON HANDLER")
    print(f"📝 SPARK Response Preview: {test_spark_response[:200]}...")
    print(f"🎯 Session: {test_session}")
    print(f"🤖 Model: {handler.scout_model}")
    print("="*60)
    
    response = handler.get_architecture(test_spark_response, test_session)
    
    print(f"📊 Response Length: {len(response)} characters")
    print(f"✅ Test completed for session: {test_session}")
    
    return response


if __name__ == "__main__":
    # Test FALCON handler independently
    test_falcon_handler()