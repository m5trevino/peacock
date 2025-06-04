#!/usr/bin/env python3
"""
Peacock Interactive Model Selector & Test Runner
Complete flow: Selection -> Validation -> Testing -> Initial Prompt
"""

import os
import sys
import json
import subprocess
import requests
from pathlib import Path

class PeacockModelSelector:
    def __init__(self):
        self.peacock_dir = Path.cwd()
        self.spark_dir = self.peacock_dir / "spark"
        self.env_file = self.spark_dir / ".env"
        self.api_key_file = self.peacock_dir / "api-key.txt"
        
        # Create spark directory if it doesn't exist
        self.spark_dir.mkdir(exist_ok=True)
        
        # Load API keys
        self.api_keys = self.load_api_keys()
        
        # Provider configurations
        self.providers = {
            "google": {
                "models": [
                    "gemini-2.5-flash-preview-05-20",
                    "gemini-2.0-flash",
                    "gemini-2.0-flash-preview-image-generation",
                    "gemini-2.5-flash-preview-tts"
                ],
                "api_key_var": "GOOGLE_API_KEY",
                "model_var": "GOOGLE_API_NAME"
            },
            "groq": {
                "models": [
                    "qwen-qwq-32b",
                    "deepseek-r1-distill-llama-70b", 
                    "mistral-saba-24b",
                    "meta-llama/llama-4-maverick-17b-128e-instruct",
                    "allam-2-7b",
                    "llama-3.1-8b-instant",
                    "llama3-70b-8192",
                    "gemma2-9b-it",
                    "meta-llama/llama-4-scout-17b-16e-instruct",
                    "llama3-8b-8192",
                    "compound-beta-mini",
                    "llama-3.3-70b-versatile"
                ],
                "api_key_var": "GROQ_API_KEY",
                "model_var": "GROQ_API_NAME"
            },
            "ollama": {
                "models": [],  # Will be populated dynamically
                "api_key_var": None,
                "model_var": "OLLAMA_API_NAME"
            },
            "lm-studio": {
                "models": [],  # Will be populated dynamically  
                "api_key_var": None,
                "model_var": "LMSTUDIO_API_NAME"
            }
        }

    def load_api_keys(self):
        """Load API keys from api-key.txt file"""
        keys = {}
        if self.api_key_file.exists():
            with open(self.api_key_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        # Remove $ prefix if present
                        key = key.strip().lstrip('$')
                        keys[key] = value.strip()
        return keys

    def save_api_keys(self):
        """Save API keys back to api-key.txt file"""
        with open(self.api_key_file, 'w') as f:
            f.write("# Peacock API Keys\n")
            f.write("# Format: KEY_NAME=value\n\n")
            for key, value in self.api_keys.items():
                f.write(f"${key}={value}\n")

    def display_banner(self):
        """Display Peacock banner"""
        banner = """
########################################################################################################################
  _____   ______            _____    ____     _____   _  __ 
 |  __ \ |  ____|    /\    / ____|  / __ \   / ____| | |/ /
 | |__) || |__      /  \  | |      | |  | | | |      | ' / 
 |  ___/ |  __|    / /\ \ | |      | |  | | | |      |  <  
 | |     | |____  / ____ \| |____  | |__| | | |____  | . \ 
 |_|     |______||_|    |_|\_____|  \____/   \_____| |_|\_|

########################################################################################################################
                             🦚 PEACOCK MODEL SELECTOR 🦚
                          Choose your AI provider and model
########################################################################################################################
"""
        print(banner)

    def select_provider(self):
        """Interactive provider selection"""
        print("\n🔥 SELECT YOUR AI PROVIDER:")
        print("1. Google (Gemini)")
        print("2. Groq")  
        print("3. Ollama")
        print("4. LM Studio")
        print("5. Exit")
        
        while True:
            choice = input("\nEnter your choice (1-5): ").strip()
            
            if choice == "1":
                return "google"
            elif choice == "2":
                return "groq"
            elif choice == "3":
                return "ollama"
            elif choice == "4":
                return "lm-studio"
            elif choice == "5":
                print("👋 Exiting Peacock...")
                sys.exit(0)
            else:
                print("❌ Invalid choice. Please enter 1-5.")

    def validate_api_key(self, provider):
        """Validate and potentially prompt for API key"""
        api_key_var = self.providers[provider].get("api_key_var")
        
        if not api_key_var:  # No API key needed (ollama, lm-studio)
            return True
            
        current_key = self.api_keys.get(api_key_var, "")
        
        if not current_key or current_key == "":
            print(f"\n❌ {api_key_var} is missing or empty!")
            new_key = input(f"Please enter your {provider.upper()} API key: ").strip()
            
            if not new_key:
                print("❌ API key cannot be empty!")
                return False
                
            self.api_keys[api_key_var] = new_key
            self.save_api_keys()
            print(f"✅ {api_key_var} saved!")
            
        return True

    def check_provider_availability(self, provider):
        """Check if provider is available"""
        print(f"\n🔍 Checking {provider.upper()} availability...")
        
        if provider == "google":
            api_key = self.api_keys.get('GOOGLE_API_KEY')
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
                response = requests.get(url, timeout=10)
                if response.status_code != 200:
                    print(f"❌ Google API error: {response.status_code}")
                    return False
            except Exception as e:
                print(f"❌ Google API connection failed: {e}")
                return False
                
        elif provider == "groq":
            api_key = self.api_keys.get('GROQ_API_KEY')
            try:
                url = "https://api.groq.com/openai/v1/models"
                headers = {"Authorization": f"Bearer {api_key}"}
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code != 200:
                    print(f"❌ Groq API error: {response.status_code}")
                    return False
            except Exception as e:
                print(f"❌ Groq API connection failed: {e}")
                return False
                
        elif provider == "ollama":
            try:
                result = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    print("❌ Ollama not available. Make sure it's installed and running.")
                    return False
            except (subprocess.TimeoutExpired, FileNotFoundError):
                print("❌ Ollama not available. Make sure it's installed and running.")
                return False
                
        elif provider == "lm-studio":
            try:
                response = requests.get("http://localhost:1234/v1/models", timeout=5)
                if response.status_code != 200:
                    print("❌ LM Studio not available. Make sure the server is running on localhost:1234")
                    return False
            except requests.exceptions.RequestException:
                print("❌ LM Studio not available. Make sure the server is running on localhost:1234")
                return False
                
        print(f"✅ {provider.upper()} is available!")
        return True

    def get_available_models(self, provider):
        """Get available models for the provider"""
        if provider in ["google", "groq"]:
            return self.providers[provider]["models"]
            
        elif provider == "ollama":
            try:
                result = subprocess.run(["ollama", "list"], capture_output=True, text=True)
                if result.returncode == 0:
                    models = []
                    lines = result.stdout.strip().split('\n')[1:]  # Skip header
                    for line in lines:
                        if line.strip():
                            model_name = line.split()[0]  # First column is model name
                            models.append(model_name)
                    return models
            except Exception as e:
                print(f"❌ Error getting Ollama models: {e}")
                return []
                
        elif provider == "lm-studio":
            try:
                response = requests.get("http://localhost:1234/v1/models", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    return [model["id"] for model in data.get("data", [])]
            except Exception as e:
                print(f"❌ Error getting LM Studio models: {e}")
                return []
                
        return []

    def select_model(self, provider, models):
        """Interactive model selection"""
        if not models:
            print(f"❌ No models available for {provider}")
            return None
            
        print(f"\n🤖 AVAILABLE {provider.upper()} MODELS:")
        for i, model in enumerate(models, 1):
            print(f"{i}. {model}")
        print(f"{len(models) + 1}. Go back")
        
        while True:
            try:
                choice = input(f"\nSelect model (1-{len(models) + 1}): ").strip()
                choice_num = int(choice)
                
                if 1 <= choice_num <= len(models):
                    return models[choice_num - 1]
                elif choice_num == len(models) + 1:
                    return None  # Go back
                else:
                    print(f"❌ Invalid choice. Please enter 1-{len(models) + 1}.")
            except ValueError:
                print("❌ Please enter a valid number.")

    def create_env_file(self, provider, model):
        """Create .env file with all required variables"""
        env_content = f"""# Peacock Configuration
# Generated by Peacock Model Selector

# Selected Provider and Model
PROVIDER={provider}
MODEL={model}

# API Keys
GROQ_API_KEY={self.api_keys.get('GROQ_API_KEY', '')}
GOOGLE_API_KEY={self.api_keys.get('GOOGLE_API_KEY', '')}

# Model Names for Each Provider
OLLAMA_API_NAME={model if provider == 'ollama' else ''}
GOOGLE_API_NAME={model if provider == 'google' else ''}
GROQ_API_NAME={model if provider == 'groq' else ''}
LMSTUDIO_API_NAME={model if provider == 'lm-studio' else ''}

# Brief Prompt Template
BRIEF_PROMPT=You are Spark, requirements analyst. Project: $USER_REQUEST. Give me: 1) Core objective 2) Current state 3) Target state 4) What's in scope 5) What's out of scope. Be concise and strategic.

# System Instructions
GOOGLE_INSTRUCTION=You are Spark, requirements analyst. Be concise and strategic.
"""
        
        with open(self.env_file, 'w') as f:
            f.write(env_content)
            
        print(f"\n✅ Configuration saved to {self.env_file}")

    def validate_environment(self, provider, model):
        """Validate that all environment variables are properly set"""
        print("\n🔍 VALIDATING ENVIRONMENT...")
        
        # Load the .env file we just created
        env_vars = {}
        with open(self.env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    env_vars[key] = value
        
        # Check required variables
        required_vars = ['PROVIDER', 'MODEL', 'BRIEF_PROMPT']
        
        # Add provider-specific requirements
        if provider in ['google', 'groq']:
            required_vars.append(f'{provider.upper()}_API_KEY')
        
        required_vars.append(self.providers[provider]['model_var'])
        
        missing_vars = []
        for var in required_vars:
            if var not in env_vars or not env_vars[var]:
                missing_vars.append(var)
        
        if missing_vars:
            print(f"❌ Missing environment variables: {', '.join(missing_vars)}")
            return False
        
        print("✅ Environment validation passed!")
        
        # Display current configuration
        print(f"\n📋 CURRENT CONFIGURATION:")
        print(f"   Provider: {env_vars['PROVIDER'].upper()}")
        print(f"   Model: {env_vars['MODEL']}")
        if provider in ['google', 'groq']:
            api_key = env_vars[f'{provider.upper()}_API_KEY']
            masked_key = api_key[:8] + "..." + api_key[-4:] if len(api_key) > 12 else "***"
            print(f"   API Key: {masked_key}")
        
        print(f"\n📝 BRIEF PROMPT:")
        print(f"   {env_vars['BRIEF_PROMPT']}")
        
        return True

    def test_api_connection(self, provider, model):
        """Test API connection with a simple request"""
        print(f"\n🧪 TESTING {provider.upper()} API CONNECTION...")
        
        test_prompt = "Hello, please respond with 'Connection successful!' to confirm the API is working."
        
        try:
            if provider == "groq":
                url = "https://api.groq.com/openai/v1/chat/completions"
                headers = {
                    "Authorization": f"Bearer {self.api_keys['GROQ_API_KEY']}",
                    "Content-Type": "application/json"
                }
                data = {
                    "messages": [{"role": "user", "content": test_prompt}],
                    "model": model
                }
                response = requests.post(url, headers=headers, json=data, timeout=30)
                
                if response.status_code == 200:
                    result = response.json()["choices"][0]["message"]["content"]
                    print(f"✅ API Test Response: {result[:100]}...")
                    return True
                else:
                    print(f"❌ API Test Failed: {response.status_code} - {response.text}")
                    return False
                    
            elif provider == "google":
                # Note: This is a simplified test - you'd need to implement Google's specific API
                print("✅ Google API key validated (full test would require google-genai library)")
                return True
                
            elif provider == "ollama":
                url = "http://localhost:11434/api/generate"
                data = {
                    "model": model,
                    "prompt": test_prompt,
                    "stream": False
                }
                response = requests.post(url, json=data, timeout=30)
                
                if response.status_code == 200:
                    result = response.json()["response"]
                    print(f"✅ API Test Response: {result[:100]}...")
                    return True
                else:
                    print(f"❌ API Test Failed: {response.status_code}")
                    return False
                    
            elif provider == "lm-studio":
                url = "http://localhost:1234/v1/chat/completions"
                headers = {"Content-Type": "application/json"}
                data = {
                    "model": model,
                    "messages": [{"role": "user", "content": test_prompt}],
                    "temperature": 0.7
                }
                response = requests.post(url, headers=headers, json=data, timeout=30)
                
                if response.status_code == 200:
                    result = response.json()["choices"][0]["message"]["content"]
                    print(f"✅ API Test Response: {result[:100]}...")
                    return True
                else:
                    print(f"❌ API Test Failed: {response.status_code}")
                    return False
                    
        except Exception as e:
            print(f"❌ API Test Exception: {e}")
            return False

    def get_project_description(self):
        """Get project description from user"""
        print("\n" + "="*60)
        print("🚀 PROJECT SETUP")
        print("="*60)
        
        print("\nNow let's get your project details...")
        
        while True:
            user_request = input("\n📝 Enter your project description: ").strip()
            if user_request:
                print(f"\n✅ Project: {user_request}")
                confirm = input("Is this correct? (Y/n): ").strip().lower()
                if confirm in ['', 'y', 'yes']:
                    return user_request
            else:
                print("❌ Project description cannot be empty!")

    def send_initial_prompt(self, provider, model, user_request):
        """Send initial prompt to the LLM"""
        print("\n" + "="*60)
        print("🤖 SENDING INITIAL PROMPT TO SPARK")
        print("="*60)
        
        # Create the full prompt
        prompt = f"You are Spark, requirements analyst. Project: {user_request}. Give me: 1) Core objective 2) Current state 3) Target state 4) What's in scope 5) What's out of scope. Be concise and strategic."
        
        print(f"\n📤 Sending to {provider.upper()}:")
        print(f"Model: {model}")
        print(f"Prompt: {prompt[:100]}...")
        
        try:
            if provider == "groq":
                url = "https://api.groq.com/openai/v1/chat/completions"
                headers = {
                    "Authorization": f"Bearer {self.api_keys['GROQ_API_KEY']}",
                    "Content-Type": "application/json"
                }
                data = {
                    "messages": [{"role": "user", "content": prompt}],
                    "model": model
                }
                response = requests.post(url, headers=headers, json=data, timeout=60)
                
                if response.status_code == 200:
                    result = response.json()["choices"][0]["message"]["content"]
                    print(f"\n📥 SPARK RESPONSE:")
                    print("="*60)
                    print(result)
                    print("="*60)
                    return result
                else:
                    print(f"❌ Request Failed: {response.status_code} - {response.text}")
                    return None
                    
            # Add other providers here as needed
            else:
                print(f"⚠️  Initial prompt sending not yet implemented for {provider}")
                return None
                
        except Exception as e:
            print(f"❌ Error sending prompt: {e}")
            return None

    def run(self):
        """Main execution flow"""
        self.display_banner()
        
        while True:
            # Step 1: Select Provider
            provider = self.select_provider()
            
            # Step 2: Validate API Key
            if not self.validate_api_key(provider):
                continue
                
            # Step 3: Check Provider Availability
            if not self.check_provider_availability(provider):
                print(f"\n❌ {provider.upper()} is not available. Please choose another provider.")
                continue
                
            # Step 4: Get and Select Model
            models = self.get_available_models(provider)
            selected_model = self.select_model(provider, models)
            
            if selected_model is None:
                continue  # Go back to provider selection
                
            # Step 5: Create Environment File
            self.create_env_file(provider, selected_model)
            
            # Step 6: Validate Environment
            if not self.validate_environment(provider, selected_model):
                print("❌ Environment validation failed!")
                continue
                
            # Step 7: Test API Connection
            if not self.test_api_connection(provider, selected_model):
                print("❌ API connection test failed!")
                continue
                
            print("\n🎉 CONFIGURATION SUCCESSFUL!")
            
            # Step 8: Get Project Description
            user_request = self.get_project_description()
            
            # Step 9: Send Initial Prompt
            response = self.send_initial_prompt(provider, selected_model, user_request)
            
            if response:
                print(f"\n✅ SUCCESS! Peacock Stage 1 (Spark) completed!")
                print("\n🔥 Next Step: Run Falcon (Stage 2) for detailed implementation planning")
            
            # Ask if user wants to try again
            again = input("\nWould you like to try a different configuration? (y/N): ").strip().lower()
            if again not in ['y', 'yes']:
                break

if __name__ == "__main__":
    selector = PeacockModelSelector()
    selector.run()
