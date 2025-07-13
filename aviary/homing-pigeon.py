#!/usr/bin/env python3
"""
homing-pigeon.py - HAWK API Handler 
Replaces HAWK orchestration logic from out_homing.py for MAVERICK model calls
"""

import os
import json
import requests
import datetime
from pathlib import Path
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()

from hawk import HawkTester


class HawkHandler:
    """HAWK API Handler - Manages MAVERICK model calls for HAWK QA analysis"""
    
    def __init__(self, broadcaster=None):
        self.stage_name = "HOMING-PIGEON"
        self.icon = "🏠"
        self.specialty = "HAWK API Communication"
        self.maverick_model = "meta-llama/llama-4-maverick-17b-128e-instruct"
        
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
        
        # Standard model parameters for MAVERICK
        self.model_params = {
            "temperature": 0.2,
            "top_p": 0.8,
            "max_tokens": 2048
        }
        
        # Initialize HAWK QA specialist
        self.hawk_qa_specialist = HawkTester()
        self.broadcaster = broadcaster
    
    def get_qa_plan(self, eagle_response: str, session_id: str) -> str:
        """
        Main handler method - gets HAWK QA analysis from MAVERICK model
        
        Args:
            eagle_response: The raw EAGLE response text
            session_id: Session identifier for logging
            
        Returns:
            Raw LLM response text
        """
        print(f"🏠 HOMING-PIGEON: Handling HAWK QA analysis for session {session_id}")
        
        try:
            # Prepare eagle implementation in expected format
            eagle_implementation = {
                "raw_implementation": eagle_response,
                "implementation": eagle_response,
                "code_files": [],
                "json_data": {}
            }
            
            # Get prompt data from HawkQASpecialist
            hawk_data = self.hawk_qa_specialist.develop_qa_strategy(eagle_implementation)
            prompt = hawk_data["prompt"]
            
            # Log the prompt
            self._log_prompt(prompt, session_id)
            
            # Make API call to MAVERICK model
            response_text = self._call_maverick_model(prompt)
            
            # Log the response
            self._log_response(response_text, session_id)
            
            print(f"✅ HOMING-PIGEON: HAWK QA analysis completed successfully")
            return response_text
            
        except Exception as e:
            error_msg = f"HOMING-PIGEON API call failed: {str(e)}"
            print(f"❌ {error_msg}")
            
            # Log the error
            self._log_error(error_msg, session_id)
            return f"# API CALL FAILED\n{error_msg}"
    
    def _call_maverick_model(self, prompt: str) -> str:
        """Make API call to MAVERICK model via Groq"""
        
        if not self.groq_api_keys:
            raise Exception("No GROQ API keys available")
        
        # Get current API key
        api_key = self.groq_api_keys[self.current_key_index % len(self.groq_api_keys)]
        
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.maverick_model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            **self.model_params
        }
        
        try:
            print(f"🌐 Calling MAVERICK model: {self.maverick_model}")
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
                    self.broadcaster.send({"stage": "HAWK", "status": "COMPLETED", "char_count": char_count})
                print(f"✅ MAVERICK model response received: {len(content)} characters")
                
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
                    return self._call_maverick_model(prompt)
                else:
                    raise Exception(error_msg)
                    
        except requests.exceptions.RequestException as e:
            raise Exception(f"Network error: {str(e)}")
    
    def _log_prompt(self, prompt: str, session_id: str):
        """Log the HAWK prompt to logs/{session_id}/07_hawk_prompt.txt"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        prompt_file = log_dir / "07_hawk_prompt.txt"
        
        with open(prompt_file, 'w', encoding='utf-8') as f:
            f.write(f"# HAWK PROMPT - {datetime.datetime.now().isoformat()}\n")
            f.write(f"# Model: {self.maverick_model}\n")
            f.write(f"# Session: {session_id}\n")
            f.write("# " + "="*70 + "\n\n")
            f.write(prompt)
        
        print(f"📝 Logged HAWK prompt: {prompt_file}")
    
    def _log_response(self, response_text: str, session_id: str):
        """Log the raw JSON response to logs/{session_id}/08_hawk_response.json"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        response_file = log_dir / "08_hawk_response.json"
        
        # Create structured response data
        response_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "model": self.maverick_model,
            "session_id": session_id,
            "stage": "HAWK",
            "response_length": len(response_text),
            "raw_response": response_text,
            "metadata": {
                "api_handler": "HOMING-PIGEON",
                "model_params": self.model_params,
                "api_key_index": self.current_key_index
            }
        }
        
        with open(response_file, 'w', encoding='utf-8') as f:
            json.dump(response_data, f, indent=2, ensure_ascii=False)
        
        print(f"💾 Logged HAWK response: {response_file}")
    
    def _log_error(self, error_msg: str, session_id: str):
        """Log errors to the session directory"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        error_file = log_dir / "hawk_error.log"
        
        with open(error_file, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.datetime.now().isoformat()}] {error_msg}\n")
        
        print(f"🚨 Logged error: {error_file}")


def create_hawk_handler(broadcaster=None) -> HawkHandler:
    """Factory function to create HawkHandler instance"""
    return HawkHandler(broadcaster=broadcaster)


def test_hawk_handler():
    """Test the HAWK handler with sample input"""
    handler = create_hawk_handler()
    
    test_eagle_response = """**PROJECT OVERVIEW:**
Complete enterprise task management web application with React frontend, Node.js backend, PostgreSQL database, and comprehensive real-time collaboration features.

**COMPLETE CODE FILES:**

**Configuration & Setup Files:**

filename: package.json
{
  "name": "task-management-app",
  "version": "1.0.0",
  "description": "Enterprise task management with real-time collaboration",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "build": "react-scripts build",
    "test": "jest"
  },
  "dependencies": {
    "express": "^4.18.2",
    "react": "^18.2.0",
    "socket.io": "^4.7.2",
    "postgresql": "^3.2.1"
  }
}

filename: server.js
[Complete Express.js server with authentication, WebSocket support, and comprehensive API endpoints]"""
    
    test_session = "test-session-hawk-001"
    
    print("🧪 TESTING HOMING-PIGEON HAWK HANDLER")
    print(f"📝 EAGLE Response Preview: {test_eagle_response[:200]}...")
    print(f"🎯 Session: {test_session}")
    print(f"🤖 Model: {handler.maverick_model}")
    print("="*60)
    
    response = handler.get_qa_plan(test_eagle_response, test_session)
    
    print(f"📊 Response Length: {len(response)} characters")
    print(f"✅ Test completed for session: {test_session}")
    
    return response


if __name__ == "__main__":
    # Test HAWK handler independently
    test_hawk_handler()