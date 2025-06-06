
####START OF DOCUMENT####
#!/usr/bin/env python3
"""
Peacock Universal API Handler System
Handles all LLM provider APIs with proper formatting and error handling
"""

import requests
import json
import os
from typing import Dict, Any, Optional
import time
from pathlib import Path

class PeacockAPIManager:
    """Universal API manager for all LLM providers"""
    
    def __init__(self, config_file=".env"):
        self.config = self.load_config(config_file)
        self.providers = {
            "groq": GroqAPIHandler(self.config),
            "google": GoogleAPIHandler(self.config),
            "ollama": OllamaAPIHandler(self.config),
            "lmstudio": LMStudioAPIHandler(self.config)
        }
        
    def load_config(self, config_file):
        """Load configuration from .env file"""
        config = {}
        config_path = Path(config_file)
        
        if config_path.exists():
            with open(config_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        # Handle the $ prefix format
                        key, value = line.split('=', 1)
                        key = key.strip().lstrip('$')
                        config[key] = value.strip()
        
        return config
    
    def get_provider(self, provider_name):
        """Get API handler for specific provider"""
        return self.providers.get(provider_name.lower())
    
    def send_request(self, provider_name, prompt, model=None, system_instruction=None):
        """Universal send request method"""
        provider = self.get_provider(provider_name)
        if not provider:
            return {"error": f"Unknown provider: {provider_name}"}
        
        return provider.send_request(prompt, model, system_instruction)


class GroqAPIHandler:
    """Groq API handler with proper formatting"""
    
    def __init__(self, config):
        self.api_key = config.get('GROQ_API_KEY', '')
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"
        self.default_model = config.get('GROQ_API_NAME', 'qwen-qwq-32b')
        
    def send_request(self, prompt, model=None, system_instruction=None):
        """Send request to Groq API"""
        if not self.api_key:
            return {"error": "GROQ_API_KEY not found in config"}
            
        model = model or self.default_model
        
        # Build messages array
        messages = []
        
        if system_instruction:
            messages.append({
                "role": "system",
                "content": system_instruction
            })
            
        messages.append({
            "role": "user", 
            "content": prompt
        })
        
        payload = {
            "messages": messages,
            "model": model,
            "temperature": 0.1,
            "max_tokens": 8192
        }
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        try:
            print(f"🔄 Sending to Groq ({model})...")
            response = requests.post(
                self.base_url, 
                json=payload, 
                headers=headers,
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result["choices"][0]["message"]["content"]
                return {
                    "success": True,
                    "content": content,
                    "provider": "groq",
                    "model": model
                }
            else:

####1/4 MARKER####
                return {
                    "error": f"Groq API error: {response.status_code}",
                    "details": response.text
                }
                
        except Exception as e:
            return {"error": f"Groq request failed: {str(e)}"}


class GoogleAPIHandler:
    """Google Gemini API handler with proper formatting"""
    
    def __init__(self, config):
        self.api_key = config.get('GOOGLE_API_KEY', '')
        self.default_model = config.get('GOOGLE_API_NAME', 'gemini-2.0-flash')
        self.system_instruction = config.get('GOOGLE_INSTRUCTION', '')
        
    def send_request(self, prompt, model=None, system_instruction=None):
        """Send request to Google Gemini API"""
        if not self.api_key:
            return {"error": "GOOGLE_API_KEY not found in config"}
            
        model = model or self.default_model
        system_inst = system_instruction or self.system_instruction
        
        # Google API URL format
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.api_key}"
        
        # Build payload for Google format
        payload = {
            "contents": [{
                "parts": [{
                    "text": prompt
                }]
            }]
        }
        
        # Add system instruction if provided
        if system_inst:
            payload["systemInstruction"] = {
                "parts": [{
                    "text": system_inst
                }]
            }
        
        headers = {
            "Content-Type": "application/json"
        }
        
        try:
            print(f"🔄 Sending to Google ({model})...")
            response = requests.post(url, json=payload, headers=headers, timeout=60)
            
            if response.status_code == 200:
                result = response.json()
                content = result["candidates"][0]["content"]["parts"][0]["text"]
                return {
                    "success": True,
                    "content": content,
                    "provider": "google",
                    "model": model
                }
            else:
                return {
                    "error": f"Google API error: {response.status_code}",
                    "details": response.text
                }
                
        except Exception as e:
            return {"error": f"Google request failed: {str(e)}"}


class OllamaAPIHandler:
    """Ollama local API handler"""
    
    def __init__(self, config):
        self.base_url = "http://localhost:11434/api/generate"
        self.default_model = config.get('OLLAMA_API_NAME', 'llama3')
        
    def send_request(self, prompt, model=None, system_instruction=None):
        """Send request to Ollama API"""
        model = model or self.default_model
        
        # Build full prompt with system instruction
        full_prompt = prompt
        if system_instruction:
            full_prompt = f"{system_instruction}\n\n{prompt}"
        
        payload = {
            "model": model,
            "prompt": full_prompt,
            "stream": False
        }
        
        try:
            print(f"🔄 Sending to Ollama ({model})...")
            response = requests.post(
                self.base_url, 
                json=payload,
                timeout=120
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result.get("response", "")
                return {
                    "success": True,
                    "content": content,
                    "provider": "ollama", 
                    "model": model
                }
            else:
                return {
                    "error": f"Ollama API error: {response.status_code}",
                    "details": response.text
                }

####1/2 MARKER####
                
        except requests.exceptions.ConnectionError:
            return {"error": "Ollama not running. Start with: ollama serve"}
        except Exception as e:
            return {"error": f"Ollama request failed: {str(e)}"}


class LMStudioAPIHandler:
    """LM Studio local API handler"""
    
    def __init__(self, config):
        self.base_url = "http://localhost:1234/v1/chat/completions"
        self.default_model = config.get('LMSTUDIO_API_NAME', 'local-model')
        
    def send_request(self, prompt, model=None, system_instruction=None):
        """Send request to LM Studio API"""
        model = model or self.default_model
        
        # Build messages array
        messages = []
        
        if system_instruction:
            messages.append({
                "role": "system",
                "content": system_instruction
            })
            
        messages.append({
            "role": "user",
            "content": prompt
        })
        
        payload = {
            "model": model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": 8192
        }
        
        headers = {
            "Content-Type": "application/json"
        }
        
        try:
            print(f"🔄 Sending to LM Studio ({model})...")
            response = requests.post(
                self.base_url,
                json=payload,
                headers=headers,
                timeout=120
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result["choices"][0]["message"]["content"]
                return {
                    "success": True,
                    "content": content,
                    "provider": "lmstudio",
                    "model": model
                }
            else:
                return {
                    "error": f"LM Studio API error: {response.status_code}",
                    "details": response.text
                }
                
        except requests.exceptions.ConnectionError:
            return {"error": "LM Studio not running. Start server on localhost:1234"}
        except Exception as e:
            return {"error": f"LM Studio request failed: {str(e)}"}


# ENHANCED BRIDGE WITH PROPER API HANDLING
class EnhancedPeacockBridge:
    """Enhanced bridge using the universal API manager"""
    
    def __init__(self, config_file=".env"):
        self.api_manager = PeacockAPIManager(config_file)
        self.mcp_url = "http://127.0.0.1:8000"
        
    def send_spark_analysis(self, user_request, provider="groq", model=None):
        """Send initial Spark analysis using specified provider"""
        spark_prompt = f"""You are Spark, requirements analyst. Project: {user_request}. 

Give me: 
1) Core objective 
2) Current state 
3) Target state 
4) What's in scope 
5) What's out of scope. 

Be concise and strategic."""

        result = self.api_manager.send_request(provider, spark_prompt, model)
        
        if result.get("success"):
            print("✅ Spark analysis complete")
            return result["content"]
        else:
            print(f"❌ Spark analysis failed: {result.get('error')}")
            return None
            
    def send_to_mcp(self, spark_response, user_request):
        """Send Spark response to Enhanced MCP"""
        print("🔄 Sending to Enhanced MCP...")
        
        mcp_payload = {
            "command": "spark_analysis",
            "text": spark_response,
            "project_request": user_request,
            "language": "project_analysis"
        }
        
        try:

####3/4 MARKER####
            response = requests.post(
                f"{self.mcp_url}/process",
                json=mcp_payload,
                timeout=30
            )
            
            if response.status_code == 200:
                print("✅ MCP processing complete")
                return response.json()
            else:
                print(f"❌ MCP error: {response.status_code}")
                return None
                
        except requests.exceptions.ConnectionError:
            print("❌ Enhanced MCP not running on port 8000")
            return None
        except Exception as e:
            print(f"❌ MCP error: {e}")
            return None
            
    def send_to_llm2(self, mcp_output, provider="groq", model=None):
        """Send MCP output to LLM2 for code generation"""
        llm2_prompt = f"""You are LLM2 - the code generation specialist.

Generate complete, working code based on this structured specification:

{json.dumps(mcp_output, indent=2)}

Provide complete implementation with:
1. All necessary files
2. Dependencies and setup
3. Clear file structure
4. Working code with error handling
5. Documentation

Format files as:
```filename: path/to/file.ext
[complete file content]
```

Begin generation:"""

        result = self.api_manager.send_request(provider, llm2_prompt, model)
        
        if result.get("success"):
            print("✅ LLM2 code generation complete")
            return result["content"]
        else:
            print(f"❌ LLM2 failed: {result.get('error')}")
            return None
            
    def run_complete_pipeline(self, user_request, spark_provider="groq", llm2_provider="groq"):
        """Run the complete pipeline with proper API handling"""
        print("🦚 PEACOCK COMPLETE PIPELINE")
        print("=" * 50)
        
        # Step 1: Spark Analysis
        print(f"\n⚡ Step 1: Spark Analysis ({spark_provider})")
        spark_response = self.send_spark_analysis(user_request, spark_provider)
        if not spark_response:
            return None
            
        # Step 2: MCP Processing  
        print("\n🔄 Step 2: MCP Processing")
        mcp_output = self.send_to_mcp(spark_response, user_request)
        if not mcp_output:
            return None
            
        # Step 3: LLM2 Code Generation
        print(f"\n🤖 Step 3: LLM2 Code Generation ({llm2_provider})")
        llm2_code = self.send_to_llm2(mcp_output, llm2_provider)
        if not llm2_code:
            return None
            
        # Step 4: File Generation (placeholder for now)
        print("\n📁 Step 4: File Generation")
        print("Code generation complete!")
        print(f"Response length: {len(llm2_code)} characters")
        
        return {
            "spark_response": spark_response,
            "mcp_output": mcp_output,
            "llm2_code": llm2_code,
            "success": True
        }


# MAIN EXECUTION
if __name__ == "__main__":
    import sys
    
    # Get user input
    if len(sys.argv) > 1:
        user_request = " ".join(sys.argv[1:])
    else:
        user_request = input("🎯 What do you want to build? ")
        
    if not user_request.strip():
        print("❌ No project request provided")
        sys.exit(1)
        
    # Initialize bridge
    bridge = EnhancedPeacockBridge()
    
    # Run pipeline
    result = bridge.run_complete_pipeline(user_request)
    
    if result and result.get("success"):
        print("\n🎉 PIPELINE SUCCESS!")
        print("=" * 30)
        print("✅ Spark analysis complete")
        print("✅ MCP processing complete") 
        print("✅ LLM2 code generation complete")
        print("\nYour Peacock pipeline is working! 🔥")
    else:
        print("\n❌ Pipeline failed - check the steps above")

####END OF DOCUMENT####
