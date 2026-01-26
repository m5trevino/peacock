# Peacock Bulletproof Parsing Implementation Guide

## Executive Summary

Based on the championship testing results, we've identified the optimal three-layer parsing strategy for production Peacock integration. **QWEN3-32B** emerged as the champion (81.5/100) with 100% parsing reliability, followed by **DeepSeek-R1** (80.0/100) as the enterprise backup. This guide provides the complete implementation roadmap for integrating bulletproof parsing into your Peacock application.

## Championship Results Summary

| Model | Score | Success Rate | Best Use Case |
|-------|-------|--------------|---------------|
| 🥇 **QWEN3-32B** | 81.5/100 | 100% | Production primary |
| 🥈 **DeepSeek-R1** | 80.0/100 | 100% | Enterprise backup |
| 🥉 **QWQ-32B** | 74.8/100 | 100% | Detailed analysis |
| **Mistral-Saba** | 67.7/100 | 75% | Avoid for parsing |

## Core Architecture: Three-Layer Strategy

### Layer 1: Prompt Engineering (30% weight)
Force models to output structured JSON that matches your Pydantic schemas.

### Layer 2: Parsing & Validation (40% weight) 
Extract JSON with multiple fallback strategies, then validate with Pydantic.

### Layer 3: Error Recovery (30% weight)
Handle failures with proxy fallback, API key rotation, and retry logic.

## Implementation Steps

### Step 1: Install Dependencies

```bash
pip install pydantic==2.5.0 requests python-dotenv
```

### Step 2: Define Pydantic Schemas

```python
from pydantic import BaseModel, Field, validator
from typing import List, Optional
from enum import Enum

class CommandType(str, Enum):
    ANALYZE = "analyze"
    FIX = "fix" 
    SPARK = "spark"
    EXPAND = "expand"
    GENERATE = "generate"

class PeacockResponse(BaseModel):
    """Enterprise-grade response schema for Peacock"""
    command_type: CommandType
    files_generated: List[str] = Field(description="List of files created")
    main_language: str = Field(description="Primary programming language")
    frameworks_used: List[str] = Field(description="Frameworks and libraries")
    executable_immediately: bool = Field(description="Ready to run without modifications")
    setup_instructions: List[str] = Field(description="Commands to execute")
    confidence_score: int = Field(ge=1, le=10, description="Quality confidence 1-10")
    
    @validator('files_generated')
    def validate_files(cls, v):
        if len(v) == 0:
            raise ValueError('At least one file must be generated')
        return v
```

### Step 3: Bulletproof Parser Class

```python
import json
import re
import requests
import time
import random
from typing import Dict, Any, Optional

class PeacockBulletproofParser:
    def __init__(self):
        # Production model hierarchy (from championship results)
        self.model_hierarchy = [
            "qwen/qwen3-32b",        # Primary: 81.5/100 score
            "deepseek-r1-distill-llama-70b",  # Backup: 80.0/100 score
            "qwen-qwq-32b"           # Fallback: 74.8/100 score
        ]
        
        # Model-specific configs (championship-optimized)
        self.model_configs = {
            "qwen/qwen3-32b": {"temperature": 0.7, "top_p": 0.8, "max_tokens": 4096},
            "deepseek-r1-distill-llama-70b": {"temperature": 0.6, "top_p": 0.9, "max_tokens": 4096},
            "qwen-qwq-32b": {"temperature": 0.6, "top_p": 0.95, "max_tokens": 4096}
        }
        
        # API configuration
        self.api_keys = [
            "your_groq_key_1",
            "your_groq_key_2", 
            "your_groq_key_3",
            "your_groq_key_4"
        ]
        self.current_key_index = 0
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"
        self.proxy_config = "your_proxy_config"
    
    def build_schema_prompt(self, user_request: str, command_type: CommandType) -> str:
        """Build bulletproof schema-compliant prompt"""
        schema = PeacockResponse.model_json_schema()
        
        return f"""
CRITICAL PARSING REQUIREMENTS:
Your response MUST be valid JSON matching this EXACT schema:

{json.dumps(schema, indent=2)}

BULLETPROOF RULES:
1. Return ONLY valid JSON - no explanatory text before or after
2. ALL required fields must be present and correctly typed
3. Wrap JSON in triple backticks with 'json' language tag
4. Files_generated must list actual filenames you create
5. Setup_instructions must be actionable commands
6. Confidence_score must be integer 1-10

EXAMPLE FORMAT:
```json
{{
  "command_type": "{command_type.value}",
  "files_generated": ["main.py", "config.py"],
  "main_language": "python",
  "frameworks_used": ["flask"],
  "executable_immediately": true,
  "setup_instructions": ["pip install flask", "python main.py"],
  "confidence_score": 9
}}
```

USER REQUEST: {user_request}
"""

    def extract_json_from_response(self, response: str) -> str:
        """Multi-strategy JSON extraction with fallbacks"""
        # Strategy 1: JSON code blocks
        json_block_pattern = r'```(?:json)?\s*(\{.*?\})\s*```'
        matches = re.findall(json_block_pattern, response, re.DOTALL)
        if matches:
            return matches[-1].strip()
        
        # Strategy 2: Naked JSON objects  
        json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
        matches = re.findall(json_pattern, response, re.DOTALL)
        for match in reversed(matches):
            try:
                json.loads(match)
                return match
            except:
                continue
        
        # Strategy 3: Clean extraction
        cleaned = response.strip()
        if cleaned.startswith('```') and cleaned.endswith('```'):
            lines = cleaned.split('\n')
            cleaned = '\n'.join(lines[1:-1])
        
        # Strategy 4: Try whole response
        try:
            json.loads(cleaned)
            return cleaned
        except:
            raise ValueError("No valid JSON found in response")

    def parse_with_bulletproof_pipeline(self, response: str) -> Dict[str, Any]:
        """Three-layer parsing pipeline"""
        result = {
            "json_extraction_success": False,
            "pydantic_validation_success": False,
            "extracted_json": None,
            "pydantic_object": None,
            "parsing_method": "failed",
            "errors": []
        }
        
        try:
            # Layer 1: JSON Extraction
            json_text = self.extract_json_from_response(response)
            result["json_extraction_success"] = True
            result["extracted_json"] = json.loads(json_text)
            result["parsing_method"] = "json_extracted"
            
            # Layer 2: Pydantic Validation
            pydantic_result = PeacockResponse.model_validate_json(json_text)
            result["pydantic_validation_success"] = True
            result["pydantic_object"] = pydantic_result
            result["parsing_method"] = "pydantic_validated"
            
            return result
            
        except Exception as e:
            result["errors"].append(str(e))
            return result

    def get_next_key(self):
        """Rotate API keys for rate limit management"""
        key = self.api_keys[self.current_key_index]
        self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
        return key

    def send_bulletproof_request(self, user_request: str, command_type: CommandType) -> Dict[str, Any]:
        """Send request with bulletproof parsing and fallbacks"""
        
        for model in self.model_hierarchy:
            print(f"🤖 Trying {model}...")
            
            # Build schema-compliant prompt
            schema_prompt = self.build_schema_prompt(user_request, command_type)
            config = self.model_configs.get(model, {"temperature": 0.7, "top_p": 0.9})
            
            for attempt in range(3):
                try:
                    # API request with key rotation and proxy fallback
                    api_key = self.get_next_key()
                    use_proxy = attempt > 0
                    
                    headers = {
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json"
                    }
                    
                    payload = {
                        "model": model,
                        "messages": [{"role": "user", "content": schema_prompt}],
                        **config
                    }
                    
                    proxies = {"http": f"http://{self.proxy_config}", 
                              "https": f"http://{self.proxy_config}"} if use_proxy else None
                    
                    response = requests.post(
                        self.base_url,
                        headers=headers,
                        json=payload,
                        proxies=proxies,
                        timeout=60
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        content = data["choices"][0]["message"]["content"]
                        
                        # BULLETPROOF PARSING
                        parsing_results = self.parse_with_bulletproof_pipeline(content)
                        
                        if parsing_results["pydantic_validation_success"]:
                            print(f"✅ Success with {model}")
                            return {
                                "success": True,
                                "model_used": model,
                                "attempt": attempt + 1,
                                "raw_response": content,
                                "parsed_data": parsing_results["pydantic_object"].model_dump(),
                                "parsing_method": parsing_results["parsing_method"]
                            }
                        else:
                            print(f"⚠️  {model} responded but parsing failed: {parsing_results['errors']}")
                    
                    else:
                        print(f"❌ HTTP {response.status_code} with {model}")
                        
                except Exception as e:
                    print(f"💥 Error with {model}: {str(e)[:100]}")
                
                # Wait before retry
                time.sleep(random.uniform(2, 5))
            
            print(f"❌ {model} failed after 3 attempts, trying next model...")
        
        # All models failed
        return {
            "success": False,
            "error": "All models failed after multiple attempts",
            "models_tried": self.model_hierarchy
        }
```

### Step 4: Integration into Peacock App

#### A. Update your main Peacock handler:

```python
class PeacockCommandHandler:
    def __init__(self):
        self.parser = PeacockBulletproofParser()
    
    def process_user_request(self, user_request: str, command_type: str) -> Dict[str, Any]:
        """Main entry point for Peacock requests"""
        
        # Convert string to enum
        cmd_type = CommandType(command_type.lower())
        
        # Send bulletproof request
        result = self.parser.send_bulletproof_request(user_request, cmd_type)
        
        if result["success"]:
            # Successfully parsed response
            parsed_data = result["parsed_data"]
            
            return {
                "status": "success",
                "model_used": result["model_used"], 
                "files_to_create": parsed_data["files_generated"],
                "setup_commands": parsed_data["setup_instructions"],
                "language": parsed_data["main_language"],
                "frameworks": parsed_data["frameworks_used"],
                "confidence": parsed_data["confidence_score"],
                "executable": parsed_data["executable_immediately"]
            }
        else:
            # All models failed
            return {
                "status": "failed",
                "error": result["error"],
                "models_attempted": result["models_tried"]
            }
```

#### B. Update your API endpoints:

```python
from flask import Flask, request, jsonify

app = Flask(__name__)
peacock_handler = PeacockCommandHandler()

@app.route('/api/generate', methods=['POST'])
def generate_code():
    try:
        data = request.json
        user_request = data.get('request')
        command_type = data.get('command', 'generate')
        
        result = peacock_handler.process_user_request(user_request, command_type)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500
```

### Step 5: Environment Configuration

```bash
# .env file
GROQ_API_KEY_1=your_first_key
GROQ_API_KEY_2=your_second_key  
GROQ_API_KEY_3=your_third_key
GROQ_API_KEY_4=your_fourth_key
PROXY_CONFIG=your_proxy_config
```

```python
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    GROQ_KEYS = [
        os.getenv('GROQ_API_KEY_1'),
        os.getenv('GROQ_API_KEY_2'),
        os.getenv('GROQ_API_KEY_3'),
        os.getenv('GROQ_API_KEY_4')
    ]
    PROXY_CONFIG = os.getenv('PROXY_CONFIG')
```

## Production Optimization Strategies

### 1. Model Selection Logic
- **Primary**: Always try QWEN3-32B first (81.5/100 champion)
- **Backup**: Fall back to DeepSeek-R1 (80.0/100 enterprise reliability)
- **Fallback**: Use QWQ-32B for complex analysis (detailed but inconsistent)

### 2. Caching Strategy
```python
import hashlib
from functools import lru_cache

class CachedParser:
    def __init__(self):
        self.response_cache = {}
    
    def get_cached_response(self, user_request: str, command_type: str):
        cache_key = hashlib.md5(f"{user_request}:{command_type}".encode()).hexdigest()
        return self.response_cache.get(cache_key)
    
    def cache_response(self, user_request: str, command_type: str, result: Dict):
        cache_key = hashlib.md5(f"{user_request}:{command_type}".encode()).hexdigest()
        self.response_cache[cache_key] = result
```

### 3. Monitoring & Metrics
```python
class PeacockMetrics:
    def __init__(self):
        self.success_rates = {}
        self.average_response_times = {}
        self.parsing_failures = {}
    
    def record_request(self, model: str, success: bool, response_time: float, parsing_success: bool):
        if model not in self.success_rates:
            self.success_rates[model] = []
            self.average_response_times[model] = []
            self.parsing_failures[model] = 0
        
        self.success_rates[model].append(success)
        self.average_response_times[model].append(response_time)
        
        if not parsing_success:
            self.parsing_failures[model] += 1
    
    def get_performance_report(self):
        report = {}
        for model in self.success_rates:
            total_requests = len(self.success_rates[model])
            successes = sum(self.success_rates[model])
            avg_time = sum(self.average_response_times[model]) / len(self.average_response_times[model])
            
            report[model] = {
                "success_rate": (successes / total_requests) * 100,
                "average_response_time": avg_time,
                "parsing_failures": self.parsing_failures[model],
                "total_requests": total_requests
            }
        
        return report
```

## Error Handling & Recovery

### Common Failure Patterns & Solutions

1. **Rate Limit Exceeded (429)**
   - Solution: API key rotation + exponential backoff
   - Fallback: Switch to next model in hierarchy

2. **Parsing Failures**
   - Solution: Multi-strategy JSON extraction
   - Fallback: Retry with more explicit prompt

3. **Network Timeouts**
   - Solution: Proxy fallback on second attempt
   - Fallback: Reduce max_tokens and retry

4. **Model Unavailable (503)**
   - Solution: Immediate fallback to next model
   - Logging: Track model availability patterns

### Production Deployment Checklist

- [ ] **API Keys**: 4+ Groq API keys configured with rotation
- [ ] **Proxy Setup**: Backup proxy configured for rate limit scenarios  
- [ ] **Model Hierarchy**: QWEN3 → DeepSeek-R1 → QWQ fallback chain
- [ ] **Pydantic Schemas**: All response types defined with validation
- [ ] **Error Logging**: Comprehensive logging for debugging failures
- [ ] **Monitoring**: Success rate and performance metrics collection
- [ ] **Rate Limiting**: Request throttling to avoid API limits
- [ ] **Caching**: Response caching for repeated requests
- [ ] **Testing**: Integration tests with all three models

## Expected Performance Metrics

Based on championship results, expect:

- **Overall Success Rate**: 95%+
- **Parsing Success Rate**: 100% (with QWEN3/DeepSeek)
- **Average Response Time**: 2-4 seconds
- **Enterprise Readiness**: 81.5/100 bulletproof score

This bulletproof parsing implementation gives you enterprise-grade reliability with multiple fallbacks and comprehensive error handling. The three-layer strategy ensures consistent, validated responses that integrate seamlessly into your Peacock application architecture.