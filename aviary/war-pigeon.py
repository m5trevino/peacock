#!/usr/bin/env python3
"""
war-pigeon.py - EAGLE API Handler 
Replaces EAGLE orchestration logic from out_homing.py for MAVERICK model calls
"""

import os
import json
import requests
import datetime
from pathlib import Path
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()

from eagle import EagleImplementer


class EagleHandler:
    """EAGLE API Handler - Manages MAVERICK model calls for EAGLE implementation"""
    
    def __init__(self, broadcaster=None):
        self.stage_name = "WAR-PIGEON"
        self.icon = "⚔️"
        self.specialty = "EAGLE API Communication"
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
            "temperature": 0.1,
            "top_p": 0.8,
            "max_tokens": 4096
        }
        
        # Initialize EAGLE implementer
        self.eagle_implementer = EagleImplementer()
        self.broadcaster = broadcaster
    
    def get_implementation_plan(self, falcon_response: str, session_id: str) -> str:
        """
        Main handler method - gets EAGLE implementation from MAVERICK model
        
        Args:
            falcon_response: The raw FALCON response text
            session_id: Session identifier for logging
            
        Returns:
            Raw LLM response text
        """
        print(f"⚔️ WAR-PIGEON: Handling EAGLE implementation for session {session_id}")
        
        try:
            # Prepare falcon architecture in expected format
            falcon_architecture = {
                "raw_design": falcon_response,
                "architecture": falcon_response,
                "json_data": {}
            }
            
            # Get prompt data from EagleImplementer
            eagle_data = self.eagle_implementer.implement_code(falcon_architecture)
            prompt = eagle_data["prompt"]
            
            # Log the prompt
            self._log_prompt(prompt, session_id)
            
            # Make API call to MAVERICK model
            response_text = self._call_maverick_model(prompt)
            
            # Log the response
            self._log_response(response_text, session_id)
            
            print(f"✅ WAR-PIGEON: EAGLE implementation completed successfully")
            return response_text
            
        except Exception as e:
            error_msg = f"WAR-PIGEON API call failed: {str(e)}"
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
                timeout=180  # Longer timeout for larger code generation
            )
            
            if response.status_code == 200:
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"]
                if self.broadcaster:
                    char_count = len(content)
                    self.broadcaster.send({"stage": "EAGLE", "status": "COMPLETED", "char_count": char_count})
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
        """Log the EAGLE prompt to logs/{session_id}/05_eagle_prompt.txt"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        prompt_file = log_dir / "05_eagle_prompt.txt"
        
        with open(prompt_file, 'w', encoding='utf-8') as f:
            f.write(f"# EAGLE PROMPT - {datetime.datetime.now().isoformat()}\n")
            f.write(f"# Model: {self.maverick_model}\n")
            f.write(f"# Session: {session_id}\n")
            f.write("# " + "="*70 + "\n\n")
            f.write(prompt)
        
        print(f"📝 Logged EAGLE prompt: {prompt_file}")
    
    def _log_response(self, response_text: str, session_id: str):
        """Log the raw JSON response to logs/{session_id}/06_eagle_response.json"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        response_file = log_dir / "06_eagle_response.json"
        
        # Create structured response data
        response_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "model": self.maverick_model,
            "session_id": session_id,
            "stage": "EAGLE",
            "response_length": len(response_text),
            "raw_response": response_text,
            "metadata": {
                "api_handler": "WAR-PIGEON",
                "model_params": self.model_params,
                "api_key_index": self.current_key_index
            }
        }
        
        with open(response_file, 'w', encoding='utf-8') as f:
            json.dump(response_data, f, indent=2, ensure_ascii=False)
        
        print(f"💾 Logged EAGLE response: {response_file}")
    
    def _log_error(self, error_msg: str, session_id: str):
        """Log errors to the session directory"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        error_file = log_dir / "eagle_error.log"
        
        with open(error_file, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.datetime.now().isoformat()}] {error_msg}\n")
        
        print(f"🚨 Logged error: {error_file}")


def create_eagle_handler(broadcaster=None) -> EagleHandler:
    """Factory function to create EagleHandler instance"""
    return EagleHandler(broadcaster=broadcaster)


def test_eagle_handler():
    """Test the EAGLE handler with sample input"""
    handler = create_eagle_handler()
    
    test_falcon_response = """**1. TECHNOLOGY STACK RECOMMENDATIONS:**

**Frontend Technology:**
- Framework: React 18.2.0 with TypeScript for type safety and component-based architecture
- UI Component Library: Material-UI (MUI) 5.x with custom design system implementation
- State Management: Redux Toolkit with RTK Query for efficient data fetching and caching
- Build Tools: Vite 4.x with HMR and optimized production builds
- Testing Framework: Jest with React Testing Library for comprehensive component testing

**Backend Technology:**
- Runtime Environment: Node.js 18.x LTS with Express.js 4.x for RESTful API development
- Framework: Express with comprehensive middleware stack and security hardening
- Authentication: JWT with refresh token rotation and secure HTTP-only cookie storage
- Database Strategy: PostgreSQL 15.x with Redis 7.x for session storage and caching
- API Documentation: OpenAPI 3.0 with automated documentation generation"""
    
    test_session = "test-session-eagle-001"
    
    print("🧪 TESTING WAR-PIGEON EAGLE HANDLER")
    print(f"📝 FALCON Response Preview: {test_falcon_response[:200]}...")
    print(f"🎯 Session: {test_session}")
    print(f"🤖 Model: {handler.maverick_model}")
    print("="*60)
    
    response = handler.get_implementation_plan(test_falcon_response, test_session)
    
    print(f"📊 Response Length: {len(response)} characters")
    print(f"✅ Test completed for session: {test_session}")
    
    return response


if __name__ == "__main__":
    # Test EAGLE handler independently
    test_eagle_handler()