#!/usr/bin/env python3
"""
🦚 PEACOCK ENHANCED ROBUST PARSER - QWEN CHAMPIONSHIP EDITION
Implements bulletproof parsing based on championship results from notes
- QWEN3-32B: 81.5/100 score (Primary)
- DeepSeek-R1: 80.0/100 score (Backup) 
- QWQ-32B: 74.8/100 score (Fallback)
"""

import json
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
from pydantic import BaseModel, Field, validator
from schemas import CodeFile, FinalCodeOutput

class ParseMethod(Enum):
    QWEN_PYDANTIC = "qwen_pydantic"      # Primary: Pydantic schema validation
    FILENAME_EXTRACTION = "filename_extraction"  # Secondary: filename: code blocks
    DIRECT_JSON = "direct_json"          # Tertiary: Direct JSON parsing
    CODE_BLOCK = "code_block"            # Quaternary: Standard code blocks
    REGEX_EXTRACTION = "regex_extraction" # Quinary: Regex fallback
    FALLBACK_RECOVERY = "fallback_recovery" # Last resort

@dataclass
class ParseResult:
    success: bool
    data: Dict[str, Any]
    method: ParseMethod
    confidence: float
    raw_response: str
    errors: List[str] = None
    qwen_parsed: Optional[FinalCodeOutput] = None
    character_count: int = 0

class EnhancedRobustParser:
    """Enhanced parser with QWEN championship integration"""
    
    def __init__(self):
        self.success_count = 0
        self.failure_count = 0
        self.method_stats = {}
        
    def parse(self, raw_response: str, command_type: str = "unknown") -> ParseResult:
        """Parse LLM response with QWEN-optimized fallback chain"""
        
        errors = []
        char_count = len(raw_response)
        
        # Check for short response warning (per notes)
        if char_count < 1000:
            errors.append(f"Response ({char_count} chars) shorter than expected (>1000)")
        
        # STRATEGY 1: QWEN Pydantic parsing (for final responses)
        if command_type in ["qwen_final", "final_generation", "generate", "peacock_full"]:
            try:
                result = self._parse_qwen_with_pydantic(raw_response)
                if result.success:
                    self._record_success(ParseMethod.QWEN_PYDANTIC)
                    result.character_count = char_count
                    return result
                errors.extend(result.errors or [])
            except Exception as e:
                errors.append(f"QWEN Pydantic failed: {str(e)}")
        
        # STRATEGY 2: Filename-based code extraction
        try:
            result = self._parse_filename_code_blocks(raw_response)
            if result.success:
                self._record_success(ParseMethod.FILENAME_EXTRACTION)
                result.character_count = char_count
                return result
            errors.extend(result.errors or [])
        except Exception as e:
            errors.append(f"Filename extraction failed: {str(e)}")
        
        # STRATEGY 3: Direct JSON parsing
        try:
            result = self._parse_direct_json(raw_response)
            if result.success:
                self._record_success(ParseMethod.DIRECT_JSON)
                result.character_count = char_count
                return result
            errors.extend(result.errors or [])
        except Exception as e:
            errors.append(f"Direct JSON failed: {str(e)}")
        
        # STRATEGY 4: Standard code blocks
        try:
            result = self._parse_code_blocks(raw_response)
            if result.success:
                self._record_success(ParseMethod.CODE_BLOCK)
                result.character_count = char_count
                return result
            errors.extend(result.errors or [])
        except Exception as e:
            errors.append(f"Code block extraction failed: {str(e)}")
        
        # STRATEGY 5: Regex-based extraction
        try:
            result = self._parse_with_regex(raw_response, command_type)
            if result.success:
                self._record_success(ParseMethod.REGEX_EXTRACTION)
                result.character_count = char_count
                return result
            errors.extend(result.errors or [])
        except Exception as e:
            errors.append(f"Regex extraction failed: {str(e)}")
        
        # STRATEGY 6: Last resort fallback
        try:
            result = self._fallback_recovery(raw_response, command_type)
            self._record_failure(ParseMethod.FALLBACK_RECOVERY)
            result.character_count = char_count
            return result
        except Exception as e:
            errors.append(f"Fallback recovery failed: {str(e)}")
        
        # Complete failure
        self._record_failure(ParseMethod.FALLBACK_RECOVERY)
        return ParseResult(
            success=False,
            data={},
            method=ParseMethod.FALLBACK_RECOVERY,
            confidence=0.0,
            raw_response=raw_response,
            errors=errors,
            character_count=char_count
        )
    
    def _parse_qwen_with_pydantic(self, response: str) -> ParseResult:
        """Parse QWEN response using Pydantic schema (championship method)"""
        
        try:
            # Extract JSON from response
            json_text = self._extract_json_from_response(response)
            if not json_text:
                raise ValueError("No JSON found in QWEN response")
            
            # Parse with Pydantic schema
            qwen_response = FinalCodeOutput.model_validate_json(json_text)
            
            # Convert to standard format for compatibility
            structured_data = {
                "project_name": qwen_response.project_name,
                "files": [file.model_dump() for file in qwen_response.files],
                "total_files": len(qwen_response.files),
                "total_characters": sum(len(f.code) for f in qwen_response.files),
                "parsed_method": "qwen_pydantic"
            }
            
            return ParseResult(
                success=True,
                data=structured_data,
                method=ParseMethod.QWEN_PYDANTIC,
                confidence=0.95,  # High confidence for schema-validated data
                raw_response=response,
                qwen_parsed=qwen_response
            )
            
        except Exception as e:
            return ParseResult(
                success=False,
                data={},
                method=ParseMethod.QWEN_PYDANTIC,
                confidence=0.0,
                raw_response=response,
                errors=[f"QWEN Pydantic parsing failed: {str(e)}"]
            )
    
    def _extract_json_from_response(self, response: str) -> Optional[str]:
        """Extract JSON from response with multiple strategies"""
        
        # Strategy 1: JSON code blocks with balanced braces
        json_block_matches = re.finditer(r'```(?:json)?\s*', response, re.DOTALL)
        for match in json_block_matches:
            start_pos = match.end()
            # Find the corresponding closing ```
            end_pattern = re.search(r'\s*```', response[start_pos:])
            if end_pattern:
                potential_json = response[start_pos:start_pos + end_pattern.start()].strip()
                if potential_json.startswith('{') and potential_json.endswith('}'):
                    try:
                        json.loads(potential_json)
                        return potential_json
                    except:
                        continue
        
        # Strategy 2: Balanced brace extraction
        brace_count = 0
        start_pos = -1
        for i, char in enumerate(response):
            if char == '{':
                if brace_count == 0:
                    start_pos = i
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0 and start_pos != -1:
                    potential_json = response[start_pos:i+1]
                    try:
                        json.loads(potential_json)
                        return potential_json
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
            return None
    
    def _parse_filename_code_blocks(self, response: str) -> ParseResult:
        """Extract code files using filename: pattern (common in QWEN responses)"""
        
        print(f"🔍 Trying filename extraction on {len(response)} chars")
        
        # Pattern for filename: followed by code block
        filename_pattern = r'```filename:\s*([^\n]+)\n(.*?)\n```'
        matches = re.findall(filename_pattern, response, re.DOTALL)
        print(f"🔍 Pattern 1 found {len(matches)} matches")
        
        if not matches:
            # Try alternative pattern for **filename: name** format
            filename_pattern = r'\*\*filename:\s*([^\*]+?)\*\*\s*```([^`]+?)```'
            matches = re.findall(filename_pattern, response, re.DOTALL)
            print(f"🔍 Pattern 2 found {len(matches)} matches")
            
        if not matches:
            # Try pattern with language hints
            filename_pattern = r'\*\*filename:\s*([^\*]+?)\*\*\s*```[a-z]*\s*\n(.*?)\n```'
            matches = re.findall(filename_pattern, response, re.DOTALL)
            print(f"🔍 Pattern 3 found {len(matches)} matches")
        
        if matches:
            files = []
            for filename, code in matches:
                filename = filename.strip()
                code = code.strip()
                
                # Clean filename by removing any parenthetical annotations
                filename = self._clean_filename(filename)
                
                # Detect language from filename
                language = self._detect_language_from_filename(filename)
                
                # Clean up any language prefixes that might be in the code
                code = self._clean_code_content(code, language)
                
                files.append({
                    "filename": filename,
                    "language": language,
                    "code": code
                })
            
            # Build structured data
            data = {
                "files": files,
                "total_files": len(files),
                "total_characters": sum(len(f["code"]) for f in files),
                "main_language": files[0]["language"] if files else "unknown",
                "parsed_method": "filename_extraction"
            }
            
            return ParseResult(
                success=True,
                data=data,
                method=ParseMethod.FILENAME_EXTRACTION,
                confidence=0.85,
                raw_response=response
            )
        
        return ParseResult(
            success=False,
            data={},
            method=ParseMethod.FILENAME_EXTRACTION,
            confidence=0.0,
            raw_response=response,
            errors=["No filename-based code blocks found"]
        )
    
    def _detect_language_from_filename(self, filename: str) -> str:
        """Detect programming language from filename extension"""
        ext_map = {
            '.py': 'python',
            '.js': 'text',  # Treat JS files as text (ignore content)
            '.html': 'html',
            '.css': 'css',
            '.json': 'json',
            '.md': 'markdown',
            '.txt': 'text',
            '.sh': 'bash',
            '.sql': 'sql',
            '.php': 'php',
            '.rb': 'ruby',
            '.go': 'go',
            '.rs': 'rust',
            '.cpp': 'cpp',
            '.c': 'c',
            '.java': 'java'
        }
        
        for ext, lang in ext_map.items():
            if filename.lower().endswith(ext):
                return lang
        
        return 'text'
    
    def _clean_code_content(self, code: str, language: str) -> str:
        """Clean up code content by removing language identifier prefixes"""
        lines = code.split('\n')
        
        # Check if first line is just the language identifier
        if lines and len(lines) > 1:
            first_line = lines[0].strip().lower()
            # If first line matches the language, remove it
            if first_line == language.lower():
                return '\n'.join(lines[1:])
            # Also check for common language identifiers
            elif first_line in ['python', 'py', 'json', 'markdown', 'md', 'bash', 'sh', 'text', 'yaml', 'sql']:
                return '\n'.join(lines[1:])
        
        return code
    
    def _clean_filename(self, filename: str) -> str:
        """Clean filename by removing annotations like (core), (utils), etc."""
        import re
        # Remove anything in parentheses at the end of filename
        cleaned = re.sub(r'\s*\([^)]+\)\s*$', '', filename)
        return cleaned.strip()
    
    def _parse_direct_json(self, response: str) -> ParseResult:
        """Try to parse the whole response as JSON"""
        cleaned = response.strip()
        
        try:
            data = json.loads(cleaned)
            return ParseResult(
                success=True,
                data=data,
                method=ParseMethod.DIRECT_JSON,
                confidence=1.0,
                raw_response=response
            )
        except json.JSONDecodeError as e:
            return ParseResult(
                success=False,
                data={},
                method=ParseMethod.DIRECT_JSON,
                confidence=0.0,
                raw_response=response,
                errors=[f"JSON decode error: {str(e)}"]
            )
    
    def _parse_code_blocks(self, response: str) -> ParseResult:
        """Extract JSON from markdown code blocks"""
        patterns = [
            r"```json\s*\n(.*?)\n```",
            r"```\s*\n(.*?)\n```",
            r"```json\s*(.*?)```",
            r"```\s*(.*?)```"
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response, re.DOTALL)
            for match in matches:
                cleaned_match = match.strip()
                try:
                    data = json.loads(cleaned_match)
                    return ParseResult(
                        success=True,
                        data=data,
                        method=ParseMethod.CODE_BLOCK,
                        confidence=0.9,
                        raw_response=response
                    )
                except json.JSONDecodeError:
                    continue
        
        return ParseResult(
            success=False,
            data={},
            method=ParseMethod.CODE_BLOCK,
            confidence=0.0,
            raw_response=response,
            errors=["No valid JSON found in code blocks"]
        )
    
    def _parse_with_regex(self, response: str, command_type: str) -> ParseResult:
        """Extract structured data using regex patterns"""
        
        data = {"command_type": command_type, "parsed_via": "regex"}
        
        # Look for confidence scores
        confidence_pattern = r"(?:confidence|score)\s*:?\s*(\d+)"
        confidence_matches = re.findall(confidence_pattern, response, re.IGNORECASE)
        if confidence_matches:
            data["confidence_score"] = int(confidence_matches[0])
        
        # Look for key findings, issues, recommendations
        findings_pattern = r"(?:findings?|issues?|problems?)\s*:?\s*\[?\s*([^\]\n]+)"
        findings_matches = re.findall(findings_pattern, response, re.IGNORECASE)
        if findings_matches:
            items = [item.strip().strip("\"'") for item in findings_matches[0].split(",") if item.strip()]
            data["key_findings"] = items
        
        # Look for recommendations
        rec_pattern = r"(?:recommendations?|suggestions?)\s*:?\s*([^\n]+)"
        rec_matches = re.findall(rec_pattern, response, re.IGNORECASE)
        if rec_matches:
            data["recommendations"] = [rec_matches[0].strip()]
        
        # Look for objectives or goals
        obj_pattern = r"(?:objective|goal|target)\s*:?\s*[\"']?(.*?)[\"']?(?:\n|$)"
        obj_matches = re.findall(obj_pattern, response, re.IGNORECASE)
        if obj_matches:
            data["core_objective"] = obj_matches[0].strip()
        
        found_data = len(data) > 2  # More than just command_type and parsed_via
        confidence = 0.7 if found_data else 0.1
        
        return ParseResult(
            success=found_data,
            data=data,
            method=ParseMethod.REGEX_EXTRACTION,
            confidence=confidence,
            raw_response=response
        )
    
    def _fallback_recovery(self, response: str, command_type: str) -> ParseResult:
        """Last resort - extract whatever we can"""
        
        data = {
            "command_type": command_type,
            "raw_content": response,
            "extraction_method": "fallback",
            "success": False,
            "message": "Parsing failed, raw content preserved",
            "character_count": len(response)
        }
        
        # Character count warning (per notes about short responses)
        if len(response) < 1000:
            data["warning"] = f"Response ({len(response)} chars) shorter than expected"
        
        # Try to find any JSON-like structures
        json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
        json_matches = re.findall(json_pattern, response)
        
        if json_matches:
            data["potential_json"] = json_matches
            # Try to parse the first potential JSON
            for potential in json_matches:
                try:
                    parsed = json.loads(potential)
                    data["extracted_json"] = parsed
                    break
                except:
                    continue
        
        # Extract any confidence scores mentioned
        confidence_pattern = r'(?:confidence|score):\s*(\d+)'
        confidence_matches = re.findall(confidence_pattern, response, re.IGNORECASE)
        if confidence_matches:
            data["confidence_score"] = int(confidence_matches[0])
        
        return ParseResult(
            success=False,  # Fallback is never "successful"
            data=data,
            method=ParseMethod.FALLBACK_RECOVERY,
            confidence=0.2,
            raw_response=response
        )
    
    def build_qwen_schema_prompt(self, user_request: str) -> str:
        """Build schema-compliant prompt for QWEN final generation"""
        
        schema = FinalCodeOutput.model_json_schema()
        
        return f"""
CRITICAL PARSING REQUIREMENTS FOR PEACOCK:
Your response MUST be valid JSON matching this EXACT schema:

{json.dumps(schema, indent=2)}

BULLETPROOF RULES:
1. Return ONLY valid JSON - no explanatory text before or after
2. ALL required fields must be present and correctly typed
3. Wrap JSON in triple backticks with 'json' language tag
4. Files array must contain actual code files with complete content
5. Each file must have filename, language, and complete code
6. CRITICAL: Use CONSISTENT filenames that match file references in your code
7. Ensure substantial code (>1000 characters total)

PYTHON PROJECT REQUIREMENTS:
- ALWAYS create Python applications unless explicitly requested otherwise
- Use proper Python project structure with separate modules
- ALWAYS include requirements.txt for dependencies
- ALWAYS include setup.py for auto-installation and running
- Use Flask for web apps, pure Python for CLI tools and games
- Create clean, well-structured Python code with proper separation of concerns

EXAMPLE FORMAT FOR PYTHON PROJECTS:
```json
{{
  "project_name": "Calculator App",
  "files": [
    {{
      "filename": "app.py",
      "language": "python",
      "code": "from flask import Flask, request, jsonify\\nfrom calculator import Calculator\\n\\napp = Flask(__name__)\\ncalc = Calculator()\\n\\n@app.route('/')\\ndef home():\\n    return 'Calculator API - Use /calculate endpoint'\\n\\n@app.route('/calculate', methods=['POST'])\\ndef calculate():\\n    data = request.get_json()\\n    operation = data.get('operation')\\n    a = float(data.get('a', 0))\\n    b = float(data.get('b', 0))\\n    \\n    if operation == 'add':\\n        result = calc.add(a, b)\\n    elif operation == 'subtract':\\n        result = calc.subtract(a, b)\\n    elif operation == 'multiply':\\n        result = calc.multiply(a, b)\\n    elif operation == 'divide':\\n        result = calc.divide(a, b)\\n    else:\\n        return jsonify({{'error': 'Invalid operation'}}), 400\\n        \\n    return jsonify({{'result': result}})\\n\\nif __name__ == '__main__':\\n    print('🧮 Calculator API starting...')\\n    print('🌐 Open http://localhost:5000')\\n    app.run(debug=True)"
    }},
    {{
      "filename": "calculator.py",
      "language": "python",
      "code": "class Calculator:\\n    def add(self, a, b):\\n        return a + b\\n    \\n    def subtract(self, a, b):\\n        return a - b\\n    \\n    def multiply(self, a, b):\\n        return a * b\\n    \\n    def divide(self, a, b):\\n        if b == 0:\\n            raise ValueError('Cannot divide by zero')\\n        return a / b"
    }},
    {{
      "filename": "requirements.txt",
      "language": "text",
      "code": "Flask==2.3.3"
    }},
    {{
      "filename": "setup.py",
      "language": "python",
      "code": "#!/usr/bin/env python3\\n\\"\\"\\"\\n🦚 Peacock App - Auto Setup & Run\\nJust run: python setup.py\\n\\"\\"\\"\\nimport subprocess\\nimport sys\\nimport os\\nfrom pathlib import Path\\n\\ndef main():\\n    print('🦚 Calculator App')\\n    print('=' * 40)\\n    \\n    # Check Python version\\n    if sys.version_info < (3, 7):\\n        print('❌ Python 3.7+ required')\\n        sys.exit(1)\\n    \\n    # Install dependencies\\n    if Path('requirements.txt').exists():\\n        print('📦 Installing dependencies...')\\n        subprocess.run([\\n            sys.executable, '-m', 'pip', 'install', \\n            '-r', 'requirements.txt', '--quiet'\\n        ])\\n        print('✅ Dependencies installed')\\n    \\n    # Run the app\\n    print('🚀 Starting application...')\\n    subprocess.run([sys.executable, 'app.py'])\\n\\nif __name__ == '__main__':\\n    main()"
    }},
    {{
      "filename": "README.md",
      "language": "markdown",
      "code": "# Calculator App\\n\\nA simple calculator API built with Python and Flask.\\n\\n## Quick Start\\n\\n```bash\\npython setup.py\\n```\\n\\nThat's it! The setup script will install dependencies and run the app.\\n\\n## Manual Setup\\n\\n```bash\\npip install -r requirements.txt\\npython app.py\\n```\\n\\n## Usage\\n\\nSend POST requests to `/calculate` with JSON:\\n\\n```json\\n{{\\n  \\"operation\\": \\"add\\",\\n  \\"a\\": 5,\\n  \\"b\\": 3\\n}}\\n```"
    }}
  ]
}}
```

CRITICAL: Make sure any file imports or references in Python code (like import statements) match actual filenames in your files array.

USER REQUEST: {user_request}

Generate complete, functional code files that implement this request.
"""
    
    def _record_success(self, method: ParseMethod):
        """Record successful parsing method"""
        self.success_count += 1
        if method.value not in self.method_stats:
            self.method_stats[method.value] = {"success": 0, "failure": 0}
        self.method_stats[method.value]["success"] += 1
    
    def _record_failure(self, method: ParseMethod):
        """Record failed parsing method"""
        self.failure_count += 1
        if method.value not in self.method_stats:
            self.method_stats[method.value] = {"success": 0, "failure": 0}
        self.method_stats[method.value]["failure"] += 1
    
    def get_championship_stats(self) -> Dict[str, Any]:
        """Get comprehensive parsing statistics"""
        total = self.success_count + self.failure_count
        success_rate = (self.success_count / total * 100) if total > 0 else 0
        
        return {
            "total_parses": total,
            "successes": self.success_count,
            "failures": self.failure_count,
            "success_rate": f"{success_rate:.1f}%",
            "method_breakdown": self.method_stats,
            "championship_ready": success_rate >= 80.0  # Based on DeepSeek-R1 benchmark
        }

# Factory function for easy integration
def create_enhanced_parser() -> EnhancedRobustParser:
    """Create enhanced parser instance"""
    return EnhancedRobustParser()

# Test the enhanced parser
if __name__ == "__main__":
    parser = EnhancedRobustParser()
    
    # Test QWEN JSON response with Python project
    qwen_response = '''```json
    {
      "project_name": "Snake Game",
      "files": [
        {
          "filename": "snake_game.py",
          "language": "python",
          "code": "import pygame\nimport random\nimport sys\n\nclass SnakeGame:\n    def __init__(self):\n        pygame.init()\n        self.width, self.height = 600, 400\n        self.screen = pygame.display.set_mode((self.width, self.height))\n        pygame.display.set_caption('Snake Game')\n        self.clock = pygame.time.Clock()\n\n    def run(self):\n        running = True\n        while running:\n            for event in pygame.event.get():\n                if event.type == pygame.QUIT:\n                    running = False\n            self.screen.fill((0, 0, 0))\n            pygame.display.flip()\n            self.clock.tick(60)\n        pygame.quit()\n\nif __name__ == '__main__':\n    game = SnakeGame()\n    game.run()",
          "size": 450
        },
        {
          "filename": "requirements.txt",
          "language": "text",
          "code": "pygame==2.5.2",
          "size": 15
        }
      ],
      "main_language": "python",
      "frameworks_used": ["pygame"],
      "executable_immediately": true,
      "setup_instructions": ["pip install -r requirements.txt", "python snake_game.py"],
      "confidence_score": 9
    }
    ```'''
    
    result = parser.parse(qwen_response, "qwen_final")
    print(f"QWEN Test: {result.method.value} - Success: {result.success}")
    print(f"Confidence: {result.confidence}")
    print(f"Files found: {result.data.get('total_files', 0)}")
    
    print(f"\nChampionship Stats: {parser.get_championship_stats()}")