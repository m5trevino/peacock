#!/usr/bin/env python3
"""
carrier-pigeon.py - SPARK API Handler 
Replaces SPARK orchestration logic from out_homing.py for SCOUT model calls
"""

import os
import json
import requests
import datetime
from pathlib import Path
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()

from spark import SparkAnalyst


class SparkHandler:
    """SPARK API Handler - Manages SCOUT model calls for SPARK analysis"""
    
    def __init__(self, broadcaster=None):
        self.stage_name = "CARRIER-PIGEON"
        self.icon = "🕊️"
        self.specialty = "SPARK API Communication"
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
            "temperature": 0.2,
            "top_p": 0.8,
            "max_tokens": 2048
        }
        
        # Initialize SPARK analyst
        self.spark_analyst = SparkAnalyst()
        self.broadcaster = broadcaster
    
    def get_analysis(self, user_request: str, session_id: str) -> str:
        """
        Main handler method - gets SPARK analysis from SCOUT model
        
        Args:
            user_request: The user's project request
            session_id: Session identifier for logging
            
        Returns:
            Raw LLM response text
        """
        print(f"🕊️ CARRIER-PIGEON: Handling SPARK analysis for session {session_id}")
        
        try:
            # Get prompt data from SparkAnalyst
            spark_data = self.spark_analyst.analyze_project_request(user_request)
            prompt = spark_data["prompt"]
            
            # Log the prompt
            self._log_prompt(prompt, session_id)
            
            # Make API call to SCOUT model
            response_text = self._call_scout_model(prompt)
            
            # Log the response
            self._log_response(response_text, session_id)
            
            print(f"✅ CARRIER-PIGEON: SPARK analysis completed successfully")
            return response_text
            
        except Exception as e:
            error_msg = f"CARRIER-PIGEON API call failed: {str(e)}"
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
                    self.broadcaster.send({"stage": "SPARK", "status": "COMPLETED", "char_count": char_count})
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
        """Log the SPARK prompt to logs/{session_id}/01_spark_prompt.txt"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        prompt_file = log_dir / "01_spark_prompt.txt"
        
        with open(prompt_file, 'w', encoding='utf-8') as f:
            f.write(f"# SPARK PROMPT - {datetime.datetime.now().isoformat()}\n")
            f.write(f"# Model: {self.scout_model}\n")
            f.write(f"# Session: {session_id}\n")
            f.write("# " + "="*70 + "\n\n")
            f.write(prompt)
        
        print(f"📝 Logged SPARK prompt: {prompt_file}")
    
    def _log_response(self, response_text: str, session_id: str):
        """Log the raw JSON response to logs/{session_id}/02_spark_response.json"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        response_file = log_dir / "02_spark_response.json"
        
        # Create structured response data
        response_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "model": self.scout_model,
            "session_id": session_id,
            "stage": "SPARK",
            "response_length": len(response_text),
            "raw_response": response_text,
            "metadata": {
                "api_handler": "CARRIER-PIGEON",
                "model_params": self.model_params,
                "api_key_index": self.current_key_index
            }
        }
        
        with open(response_file, 'w', encoding='utf-8') as f:
            json.dump(response_data, f, indent=2, ensure_ascii=False)
        
        print(f"💾 Logged SPARK response: {response_file}")
    
    def _log_error(self, error_msg: str, session_id: str):
        """Log errors to the session directory"""
        log_dir = Path(f"logs/{session_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        error_file = log_dir / "spark_error.log"
        
        with open(error_file, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.datetime.now().isoformat()}] {error_msg}\n")
        
        print(f"🚨 Logged error: {error_file}")


def create_spark_handler(broadcaster=None) -> SparkHandler:
    """Factory function to create SparkHandler instance"""
    return SparkHandler(broadcaster=broadcaster)


def test_spark_handler():
    """Test the SPARK handler with sample input"""
    handler = create_spark_handler()
    
    test_request = "Build a comprehensive task management web application with real-time collaboration features"
    test_session = "test-session-001"
    
    print("🧪 TESTING CARRIER-PIGEON SPARK HANDLER")
    print(f"📝 Request: {test_request}")
    print(f"🎯 Session: {test_session}")
    print(f"🤖 Model: {handler.scout_model}")
    print("="*60)
    
    response = handler.get_analysis(test_request, test_session)
    
    print(f"📊 Response Length: {len(response)} characters")
    print(f"✅ Test completed for session: {test_session}")
    
    return response


if __name__ == "__main__":
    # Test SPARK handler independently
    test_spark_handler()