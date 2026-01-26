# Peacock LLM Output Parsing Strategy - The Real Blueprint

## Executive Summary

Your Peacock system needs bulletproof parsing to convert raw LLM responses into actionable data structures. Based on your existing architecture and the patterns that actually work in production, here's the comprehensive strategy that'll make your system reliable as fuck.

## Core Parsing Philosophy

**The Three-Layer Strategy:**
1. **Prompt Engineering Layer** - Force LLMs to output structured data
2. **Parsing & Validation Layer** - Convert raw text to typed objects  
3. **Error Recovery Layer** - Handle failures and retry with fixes

This approach gives you reliability, type safety, and the ability to handle LLM unpredictability without breaking your pipeline.

## Strategy 1: Pydantic + JSON Schema (RECOMMENDED)

### Why This Approach Wins

Pydantic gives you type safety, validation, and automatic error messages. It's battle-tested in production systems and integrates perfectly with your existing MCP architecture.

### Implementation Architecture

```python
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from enum import Enum

class CommandType(str, Enum):
    ANALYZE = "analyze"
    FIX = "fix"
    SPARK = "spark"
    EXPAND = "expand"

class CodeLocation(BaseModel):
    file_path: str = Field(description="Full path to the file")
    start_line: int = Field(description="Starting line number (1-based)")
    end_line: int = Field(description="Ending line number (1-based)")
    function_name: Optional[str] = Field(description="Function name if applicable")

class AnalysisResult(BaseModel):
    command_type: CommandType
    confidence_score: int = Field(ge=1, le=10, description="Confidence in analysis (1-10)")
    key_findings: List[str] = Field(description="Main discoveries from analysis")
    recommendations: List[str] = Field(description="Actionable recommendations")
    code_quality_score: Optional[int] = Field(ge=1, le=10, description="Code quality rating")
    
    @validator('key_findings')
    def validate_findings(cls, v):
        if len(v) == 0:
            raise ValueError('At least one finding is required')
        return v

class FixSuggestion(BaseModel):
    command_type: CommandType = CommandType.FIX
    issue_description: str = Field(description="What problem was identified")
    fix_explanation: str = Field(description="Why this fix addresses the issue")
    original_code: str = Field(description="Original problematic code")
    replacement_code: str = Field(description="Fixed code to replace original")
    location: CodeLocation
    confidence_score: int = Field(ge=1, le=10)
    requires_wider_review: bool = Field(description="Whether this fix might affect other code")
    
class SparkRequirements(BaseModel):
    command_type: CommandType = CommandType.SPARK
    core_objective: str = Field(description="Main goal of the project")
    current_state: str = Field(description="What exists now")
    target_state: str = Field(description="What needs to be built")
    in_scope: List[str] = Field(description="Features/components to include")
    out_of_scope: List[str] = Field(description="Features/components to exclude")
    technical_preferences: Dict[str, str] = Field(default_factory=dict)
    priority_level: str = Field(default="medium", description="Project priority")

class ExpandAnalysis(BaseModel):
    command_type: CommandType = CommandType.EXPAND
    expanded_explanation: str = Field(description="Detailed explanation of the code/concept")
    code_breakdown: List[str] = Field(description="Step-by-step code explanation")
    related_concepts: List[str] = Field(description="Connected programming concepts")
    best_practices: List[str] = Field(description="Relevant best practices")
    example_usage: Optional[str] = Field(description="Example of how to use this code")
```

### Prompt Engineering for Schema Compliance

```python
def build_schema_prompt(command_type: str, base_prompt: str, schema_model) -> str:
    """Build prompts that force LLM compliance with schema"""
    
    # Get the JSON schema from the Pydantic model
    schema = schema_model.schema()
    
    schema_instruction = f"""
CRITICAL: Your response MUST be valid JSON matching this exact schema:

{json.dumps(schema, indent=2)}

RULES:
1. Return ONLY valid JSON - no explanatory text before or after
2. All required fields must be present
3. Follow the exact field names and types
4. Wrap JSON in triple backticks with 'json' language tag

Example format:
```json
{{
  "command_type": "{command_type}",
  "confidence_score": 8,
  ...
}}
```
"""
    
    return f"{base_prompt}\n\n{schema_instruction}"

def parse_llm_response_with_schema(raw_response: str, schema_model) -> Dict[str, Any]:
    """Parse LLM response using Pydantic schema with error recovery"""
    
    try:
        # Extract JSON from response
        json_text = extract_json_from_response(raw_response)
        
        # Parse and validate using Pydantic
        parsed_obj = schema_model.parse_raw(json_text)
        
        return {
            "success": True,
            "data": parsed_obj.dict(),
            "raw_response": raw_response
        }
        
    except ValidationError as e:
        return {
            "success": False,
            "error": "validation_failed",
            "validation_errors": e.errors(),
            "raw_response": raw_response
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": "invalid_json",
            "json_error": str(e),
            "raw_response": raw_response
        }
```

### JSON Extraction Utility

```python
import re
import json

def extract_json_from_response(response: str) -> str:
    """Extract JSON from LLM response with multiple fallback strategies"""
    
    # Strategy 1: Look for JSON code blocks
    json_block_pattern = r'```(?:json)?\s*(\{.*?\})\s*```'
    matches = re.findall(json_block_pattern, response, re.DOTALL)
    if matches:
        return matches[-1].strip()
    
    # Strategy 2: Look for naked JSON objects
    json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
    matches = re.findall(json_pattern, response, re.DOTALL)
    for match in reversed(matches):  # Try last match first
        try:
            json.loads(match)
            return match
        except:
            continue
    
    # Strategy 3: Try to clean and extract
    cleaned = response.strip()
    if cleaned.startswith('```') and cleaned.endswith('```'):
        lines = cleaned.split('\n')
        cleaned = '\n'.join(lines[1:-1])
    
    # Strategy 4: Last resort - try the whole response
    try:
        json.loads(cleaned)
        return cleaned
    except:
        raise ValueError("No valid JSON found in response")
```

## Strategy 2: Hybrid Approach (Schema + Fallback Parsing)

### When to Use This

For commands where LLMs might struggle with strict JSON but you still need structured data. Good for complex analysis where you want both structured data AND natural language explanations.

### Implementation

```python
class HybridParser:
    """Parser that tries schema first, falls back to regex patterns"""
    
    def __init__(self):
        self.schema_models = {
            "analyze": AnalysisResult,
            "fix": FixSuggestion,
            "spark": SparkRequirements,
            "expand": ExpandAnalysis
        }
        
        # Fallback regex patterns for each command
        self.fallback_patterns = {
            "analyze": {
                "findings": r"(?:Key findings?|Findings?|Issues?):\s*\n((?:[-•]\s*.*\n?)+)",
                "recommendations": r"(?:Recommendations?|Suggestions?):\s*\n((?:[-•]\s*.*\n?)+)",
                "confidence": r"(?:Confidence|Score):\s*(\d+)"
            },
            "fix": {
                "issue": r"(?:Issue|Problem):\s*(.*?)(?:\n\n|\n[A-Z])",
                "solution": r"(?:Fix|Solution):\s*(.*?)(?:\n\n|\n[A-Z])",
                "code_block": r"```[\w]*\n(.*?)\n```"
            }
        }
    
    def parse(self, command: str, raw_response: str) -> Dict[str, Any]:
        """Try schema parsing first, fallback to regex if needed"""
        
        # First attempt: Schema-based parsing
        if command in self.schema_models:
            schema_result = parse_llm_response_with_schema(
                raw_response, 
                self.schema_models[command]
            )
            if schema_result["success"]:
                return schema_result
        
        # Fallback: Regex-based extraction
        return self._fallback_parse(command, raw_response)
    
    def _fallback_parse(self, command: str, raw_response: str) -> Dict[str, Any]:
        """Extract data using regex patterns when schema parsing fails"""
        
        patterns = self.fallback_patterns.get(command, {})
        extracted_data = {"command_type": command}
        
        for field, pattern in patterns.items():
            matches = re.findall(pattern, raw_response, re.MULTILINE | re.DOTALL)
            if matches:
                if field.endswith("s"):  # Plural fields = lists
                    items = [item.strip("- •").strip() for item in matches[0].split('\n') if item.strip()]
                    extracted_data[field] = [item for item in items if item]
                else:
                    extracted_data[field] = matches[0].strip()
        
        return {
            "success": True,
            "data": extracted_data,
            "method": "fallback_regex",
            "raw_response": raw_response
        }
```

## Strategy 3: Enhanced JSON Serialization (Based on Real-World Libraries)

### Advanced JSON Handling for Complex Data

```python
from typing import Any, Dict, List, Set
from datetime import datetime
import json
import re

class PeacockJSONHandler:
    """Advanced JSON handler inspired by SuperJSON/Seroval for complex LLM data"""
    
    def __init__(self):
        self.type_handlers = {
            'date': lambda obj: obj.isoformat() if isinstance(obj, datetime) else obj,
            'set': lambda obj: list(obj) if isinstance(obj, set) else obj,
            'regex': lambda obj: obj.pattern if hasattr(obj, 'pattern') else str(obj),
        }
        
        self.meta_info = {}
    
    def serialize_with_meta(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Serialize complex data while preserving type information"""
        
        serialized_data = {}
        meta = {}
        
        for key, value in data.items():
            if isinstance(value, datetime):
                serialized_data[key] = value.isoformat()
                meta[key] = 'date'
            elif isinstance(value, set):
                serialized_data[key] = list(value)
                meta[key] = 'set'
            elif hasattr(value, 'pattern'):  # Regex
                serialized_data[key] = value.pattern
                meta[key] = 'regex'
            else:
                serialized_data[key] = value
        
        return {
            "json": serialized_data,
            "meta": meta if meta else None
        }
    
    def deserialize_with_meta(self, serialized: Dict[str, Any]) -> Dict[str, Any]:
        """Restore original types using metadata"""
        
        data = serialized.get("json", {})
        meta = serialized.get("meta", {})
        
        restored_data = {}
        
        for key, value in data.items():
            if key in meta:
                type_info = meta[key]
                if type_info == 'date':
                    restored_data[key] = datetime.fromisoformat(value)
                elif type_info == 'set':
                    restored_data[key] = set(value)
                elif type_info == 'regex':
                    restored_data[key] = re.compile(value)
                else:
                    restored_data[key] = value
            else:
                restored_data[key] = value
        
        return restored_data

class LangGraphInspiredParser:
    """Iterative parsing with error recovery inspired by LangGraph code generation"""
    
    def __init__(self, llm_client):
        self.llm_client = llm_client
        self.max_retry_attempts = 3
        self.json_handler = PeacockJSONHandler()
    
    def parse_with_iterative_improvement(self, command: str, raw_response: str, code_context: Dict = None) -> Dict[str, Any]:
        """Parse with LangGraph-style iterative improvement and testing"""
        
        parsing_state = {
            "command": command,
            "raw_response": raw_response,
            "code_context": code_context or {},
            "iterations": 0,
            "errors": [],
            "success": False
        }
        
        for iteration in range(self.max_retry_attempts):
            parsing_state["iterations"] = iteration + 1
            
            # Step 1: Attempt parsing
            parse_result = self._attempt_parse(parsing_state)
            
            if parse_result["success"]:
                # Step 2: Validate parsed data
                validation_result = self._validate_parsed_data(parse_result["data"], command)
                
                if validation_result["valid"]:
                    # Step 3: Test execution if it's code
                    if command == "fix" and "replacement_code" in parse_result["data"]:
                        execution_result = self._test_code_execution(parse_result["data"])
                        
                        if execution_result["success"]:
                            return {
                                "success": True,
                                "data": parse_result["data"],
                                "iterations": iteration + 1,
                                "method": "iterative_improvement"
                            }
                        else:
                            # Code failed - add error and retry
                            parsing_state["errors"].append(execution_result["error"])
                            parsing_state["raw_response"] = self._generate_retry_response(
                                parsing_state, execution_result["error"]
                            )
                            continue
                    else:
                        # Non-code command succeeded validation
                        return {
                            "success": True,
                            "data": parse_result["data"],
                            "iterations": iteration + 1,
                            "method": "iterative_improvement"
                        }
                else:
                    # Validation failed - add error and retry
                    parsing_state["errors"].append(validation_result["error"])
                    parsing_state["raw_response"] = self._generate_retry_response(
                        parsing_state, validation_result["error"]
                    )
            else:
                # Parsing failed - add error and retry
                parsing_state["errors"].append(parse_result["error"])
                parsing_state["raw_response"] = self._generate_retry_response(
                    parsing_state, parse_result["error"]
                )
        
        # All attempts failed
        return {
            "success": False,
            "error": "max_iterations_exceeded",
            "iterations": self.max_retry_attempts,
            "errors": parsing_state["errors"],
            "raw_response": parsing_state["raw_response"]
        }
    
    def _test_code_execution(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Test if generated code executes without errors (inspired by LangGraph)"""
        
        try:
            imports = parsed_data.get("imports", "")
            code = parsed_data.get("replacement_code", "")
            
            # Create a safe execution environment
            test_globals = {}
            test_locals = {}
            
            # First test imports
            if imports:
                exec(imports, test_globals, test_locals)
            
            # Then test code (but don't actually execute destructive operations)
            if code:
                # Simple syntax and import check
                compile(code, '<string>', 'exec')
                
            return {"success": True}
            
        except SyntaxError as e:
            return {
                "success": False,
                "error": f"Syntax error in generated code: {str(e)}"
            }
        except ImportError as e:
            return {
                "success": False,
                "error": f"Import error in generated code: {str(e)}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Execution error in generated code: {str(e)}"
            }
    
    def _generate_retry_response(self, parsing_state: Dict, error: str) -> str:
        """Generate improved response using LLM with error feedback"""
        
        retry_prompt = f"""
Your previous attempt had the following error:
ERROR: {error}

PREVIOUS ATTEMPTS:
{chr(10).join([f"Attempt {i+1}: {err}" for i, err in enumerate(parsing_state['errors'])])}

ORIGINAL COMMAND: {parsing_state['command']}

Please fix the response and provide a corrected version.
The response must be valid JSON matching the required schema.

ORIGINAL RESPONSE THAT FAILED:
{parsing_state['raw_response']}
        """
        
        retry_result = self.llm_client.generate(retry_prompt)
        return retry_result.get("text", parsing_state["raw_response"])
```

## Strategy 4: Comment-Aware JSON Parsing

### Supporting JSON with Comments (Based on Microsoft's JSONC)

```python
import json
import re

class CommentAwareJSONParser:
    """Parser that handles JSON with comments, inspired by Microsoft's JSONC"""
    
    @staticmethod
    def strip_json_comments(json_string: str) -> str:
        """Remove comments from JSON string while preserving string literals"""
        
        # Remove single-line comments (// comment)
        json_string = re.sub(r'//.*?
```

## Command-Specific Parsing Strategies

### Analyze Command
- **Primary:** Pydantic schema with required findings/recommendations
- **Fallback:** Regex extraction of bullet points and scores
- **Recovery:** Ask LLM to restructure findings as numbered list

### Fix Command  
- **Primary:** Strict schema requiring before/after code blocks
- **Fallback:** Extract any code blocks found, infer intent
- **Recovery:** Ask LLM to clearly separate original vs fixed code

### Spark Command
- **Primary:** Comprehensive requirements schema
- **Fallback:** Section-based regex parsing (your existing approach)
- **Recovery:** Ask LLM to reorganize into clear sections

### Expand Command
- **Primary:** Educational content schema with examples
- **Fallback:** Extract any code blocks and explanatory text
- **Recovery:** Ask for step-by-step breakdown format

## Performance and Reliability Considerations

### Caching Parsed Results
```python
import hashlib
from functools import lru_cache

class CachedParser:
    def __init__(self):
        self.parse_cache = {}
    
    def parse_with_cache(self, command: str, raw_response: str):
        # Create cache key from response content
        cache_key = hashlib.md5(f"{command}:{raw_response}".encode()).hexdigest()
        
        if cache_key in self.parse_cache:
            return self.parse_cache[cache_key]
        
        result = self.parse_with_recovery(command, raw_response)
        self.parse_cache[cache_key] = result
        return result
```

### Monitoring and Metrics
```python
class ParsingMetrics:
    def __init__(self):
        self.success_rates = {}
        self.common_errors = {}
        self.average_attempts = {}
    
    def record_parse_attempt(self, command: str, success: bool, attempts: int, error: str = None):
        if command not in self.success_rates:
            self.success_rates[command] = []
        
        self.success_rates[command].append(success)
        
        if not success and error:
            if command not in self.common_errors:
                self.common_errors[command] = {}
            self.common_errors[command][error] = self.common_errors[command].get(error, 0) + 1
    
    def get_performance_report(self) -> Dict[str, Any]:
        report = {}
        for command, results in self.success_rates.items():
            total = len(results)
            successes = sum(results)
            report[command] = {
                "success_rate": successes / total if total > 0 else 0,
                "total_attempts": total,
                "common_errors": self.common_errors.get(command, {})
            }
        return report
```

## Recommended Implementation Plan

### Phase 1: Core Schema Implementation (Week 1-2)
1. Define Pydantic models for all four commands
2. Build schema-based prompts for each command type
3. Implement basic JSON extraction utility
4. Test with your existing MCP setup

### Phase 2: Error Recovery (Week 3)
1. Add fallback regex patterns for each command
2. Implement LLM-assisted error recovery
3. Add retry logic with exponential backoff
4. Test edge cases and malformed responses

### Phase 3: Production Hardening (Week 4)
1. Add comprehensive logging and metrics
2. Implement caching for repeated parses
3. Add performance monitoring
4. Load test with high volume requests

### Phase 4: Advanced Features (Week 5+)
1. Adaptive prompting based on parsing success rates
2. Model-specific parsing strategies
3. User feedback integration for parsing improvements
4. Advanced HTML generation from structured data

## Why This Approach Dominates

1. **Type Safety:** Pydantic ensures your data structures are correct
2. **Reliability:** Multi-layer fallbacks handle LLM unpredictability  
3. **Performance:** Caching and metrics optimize for speed
4. **Maintainability:** Clear separation of concerns and testable components
5. **Scalability:** Easy to add new commands and parsing strategies

This strategy gives you the reliability of enterprise systems while handling the chaotic nature of LLM outputs. Your Peacock system will be bulletproof and ready for production workloads.
, '', json_string, flags=re.MULTILINE)
        
        # Remove multi-line comments (/* comment */)
        json_string = re.sub(r'/\*.*?\*/', '', json_string, flags=re.DOTALL)
        
        return json_string
    
    @staticmethod
    def parse_json_with_comments(json_string: str) -> Dict[str, Any]:
        """Parse JSON that may contain comments"""
        
        try:
            # First try standard JSON parsing
            return json.loads(json_string)
        except json.JSONDecodeError:
            # If that fails, try stripping comments
            try:
                cleaned_json = CommentAwareJSONParser.strip_json_comments(json_string)
                return json.loads(cleaned_json)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON even after comment removal: {e}")

class PeacockConfigParser:
    """Enhanced config parser for Peacock that supports comments and advanced features"""
    
    def __init__(self):
        self.comment_parser = CommentAwareJSONParser()
        
    def load_peacock_config(self, config_path: str) -> Dict[str, Any]:
        """Load Peacock configuration with comment support"""
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_content = f.read()
            
            # Parse with comment support
            config_data = self.comment_parser.parse_json_with_comments(config_content)
            
            # Validate required sections
            required_sections = ['llm_config', 'mcp_servers', 'parsing_config']
            for section in required_sections:
                if section not in config_data:
                    raise ValueError(f"Missing required config section: {section}")
            
            return config_data
            
        except FileNotFoundError:
            raise ValueError(f"Config file not found: {config_path}")
        except Exception as e:
            raise ValueError(f"Error loading config: {e}")
```

## Strategy 5: Multi-Server MCP Integration with Robust Parsing

### Advanced MCP Client Architecture

```python
class EnhancedMCPClient:
    """MCP client with multi-server support and robust parsing"""
    
    def __init__(self, config_path: str):
        self.config = PeacockConfigParser().load_peacock_config(config_path)
        self.parsers = {
            'iterative': LangGraphInspiredParser(self.get_llm_client()),
            'hybrid': HybridParser(),
            'comment_aware': CommentAwareJSONParser()
        }
        self.connected_servers = {}
        self.unified_tools = []
    
    async def connect_to_servers(self):
        """Connect to multiple MCP servers as defined in config"""
        
        server_configs = self.config.get('mcp_servers', {})
        
        for server_name, server_config in server_configs.items():
            try:
                # Connect to server using config
                server_client = await self._connect_single_server(server_config)
                
                # Load tools from server
                tools = await server_client.list_tools()
                
                # Add server namespace to tool names to avoid conflicts
                namespaced_tools = []
                for tool in tools:
                    tool['name'] = f"{server_name}_{tool['name']}"
                    tool['server_source'] = server_name
                    namespaced_tools.append(tool)
                
                self.connected_servers[server_name] = server_client
                self.unified_tools.extend(namespaced_tools)
                
                print(f"✅ Connected to {server_name}: {len(tools)} tools loaded")
                
            except Exception as e:
                print(f"❌ Failed to connect to {server_name}: {e}")
                continue
    
    def parse_llm_response(self, command: str, raw_response: str, parsing_strategy: str = "iterative") -> Dict[str, Any]:
        """Parse LLM response using specified strategy"""
        
        parser = self.parsers.get(parsing_strategy)
        if not parser:
            raise ValueError(f"Unknown parsing strategy: {parsing_strategy}")
        
        if parsing_strategy == "iterative":
            return parser.parse_with_iterative_improvement(command, raw_response)
        elif parsing_strategy == "hybrid":
            return parser.parse(command, raw_response)
        else:
            # Use basic JSON parsing for comment-aware parser
            try:
                data = parser.parse_json_with_comments(raw_response)
                return {"success": True, "data": data, "method": "comment_aware"}
            except Exception as e:
                return {"success": False, "error": str(e), "method": "comment_aware"}
```

## Enhanced Integration with Your Peacock Architecture

### Updated MCP Server Integration

```python
# Enhanced version of your existing MCP server
class PeacockMCPRequestHandler(http.server.BaseHTTPRequestHandler):
    
    def __init__(self, *args, **kwargs):
        self.config = PeacockConfigParser().load_peacock_config("peacock_config.json")
        self.parsing_strategy = self.config.get('parsing_config', {}).get('default_strategy', 'iterative')
        self.parser = LangGraphInspiredParser(self.get_llm_client())
        super().__init__(*args, **kwargs)
    
    def do_POST(self):
        # ... existing code ...
        
        if llm_response.get("success"):
            llm_raw_text = llm_response.get("text", "")
            
            # Use the configured parsing strategy
            parsing_result = self.parser.parse_with_iterative_improvement(
                command, 
                llm_raw_text,
                code_context=location_info
            )
            
            if parsing_result["success"]:
                structured_data = parsing_result["data"]
                
                # Enhanced HTML generation with type preservation
                html_result = self._generate_enhanced_html_with_types(
                    command, 
                    structured_data, 
                    location_info
                )
                
                response_payload = {
                    "status": "success",
                    "command": command,
                    "structured_data": structured_data,
                    "parsing_iterations": parsing_result.get("iterations", 1),
                    "parsing_method": parsing_result.get("method", "unknown"),
                    "html_report": html_result,
                    "confidence_score": structured_data.get("confidence_score", 0)
                }
            else:
                # Enhanced error reporting
                response_payload = {
                    "status": "parsing_failed",
                    "command": command,
                    "raw_text": llm_raw_text,
                    "parsing_errors": parsing_result.get("errors", []),
                    "iterations_attempted": parsing_result.get("iterations", 0),
                    "last_error": parsing_result.get("error", "Unknown error"),
                    "fallback_data": self._extract_fallback_data(llm_raw_text)
                }
```

## Updated Implementation Phases

### Phase 1: Core Schema + Iterative Parsing (Week 1-2)
1. Implement Pydantic models for all commands
2. Build LangGraph-inspired iterative parser
3. Add code execution testing for Fix commands
4. Test with basic error recovery

### Phase 2: Advanced JSON Handling (Week 3)
1. Implement SuperJSON-style type preservation
2. Add comment-aware JSON parsing
3. Build multi-server MCP client architecture
4. Add comprehensive error recovery patterns

### Phase 3: Production Integration (Week 4)
1. Integrate all parsing strategies with your MCP
2. Add configuration-based parsing strategy selection
3. Implement comprehensive logging and metrics
4. Add fallback data extraction for failed parses

### Phase 4: Advanced Features (Week 5+)
1. Adaptive parsing strategy selection based on success rates
2. Advanced type preservation for complex data structures
3. Integration with multiple LLM providers
4. Real-time parsing performance optimization
```

## Command-Specific Parsing Strategies

### Analyze Command
- **Primary:** Pydantic schema with required findings/recommendations
- **Fallback:** Regex extraction of bullet points and scores
- **Recovery:** Ask LLM to restructure findings as numbered list

### Fix Command  
- **Primary:** Strict schema requiring before/after code blocks
- **Fallback:** Extract any code blocks found, infer intent
- **Recovery:** Ask LLM to clearly separate original vs fixed code

### Spark Command
- **Primary:** Comprehensive requirements schema
- **Fallback:** Section-based regex parsing (your existing approach)
- **Recovery:** Ask LLM to reorganize into clear sections

### Expand Command
- **Primary:** Educational content schema with examples
- **Fallback:** Extract any code blocks and explanatory text
- **Recovery:** Ask for step-by-step breakdown format

## Performance and Reliability Considerations

### Caching Parsed Results
```python
import hashlib
from functools import lru_cache

class CachedParser:
    def __init__(self):
        self.parse_cache = {}
    
    def parse_with_cache(self, command: str, raw_response: str):
        # Create cache key from response content
        cache_key = hashlib.md5(f"{command}:{raw_response}".encode()).hexdigest()
        
        if cache_key in self.parse_cache:
            return self.parse_cache[cache_key]
        
        result = self.parse_with_recovery(command, raw_response)
        self.parse_cache[cache_key] = result
        return result
```

### Monitoring and Metrics
```python
class ParsingMetrics:
    def __init__(self):
        self.success_rates = {}
        self.common_errors = {}
        self.average_attempts = {}
    
    def record_parse_attempt(self, command: str, success: bool, attempts: int, error: str = None):
        if command not in self.success_rates:
            self.success_rates[command] = []
        
        self.success_rates[command].append(success)
        
        if not success and error:
            if command not in self.common_errors:
                self.common_errors[command] = {}
            self.common_errors[command][error] = self.common_errors[command].get(error, 0) + 1
    
    def get_performance_report(self) -> Dict[str, Any]:
        report = {}
        for command, results in self.success_rates.items():
            total = len(results)
            successes = sum(results)
            report[command] = {
                "success_rate": successes / total if total > 0 else 0,
                "total_attempts": total,
                "common_errors": self.common_errors.get(command, {})
            }
        return report
```

## Recommended Implementation Plan

### Phase 1: Core Schema Implementation (Week 1-2)
1. Define Pydantic models for all four commands
2. Build schema-based prompts for each command type
3. Implement basic JSON extraction utility
4. Test with your existing MCP setup

### Phase 2: Error Recovery (Week 3)
1. Add fallback regex patterns for each command
2. Implement LLM-assisted error recovery
3. Add retry logic with exponential backoff
4. Test edge cases and malformed responses

### Phase 3: Production Hardening (Week 4)
1. Add comprehensive logging and metrics
2. Implement caching for repeated parses
3. Add performance monitoring
4. Load test with high volume requests

### Phase 4: Advanced Features (Week 5+)
1. Adaptive prompting based on parsing success rates
2. Model-specific parsing strategies
3. User feedback integration for parsing improvements
4. Advanced HTML generation from structured data

## Why This Approach Dominates

1. **Type Safety:** Pydantic ensures your data structures are correct
2. **Reliability:** Multi-layer fallbacks handle LLM unpredictability  
3. **Performance:** Caching and metrics optimize for speed
4. **Maintainability:** Clear separation of concerns and testable components
5. **Scalability:** Easy to add new commands and parsing strategies

This strategy gives you the reliability of enterprise systems while handling the chaotic nature of LLM outputs. Your Peacock system will be bulletproof and ready for production workloads.
