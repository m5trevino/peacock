
#!/usr/bin/env python3
"""
eagle.py - EAGLE Code Implementation Bird
The coding beast who transforms architecture into working code
"""

import json
import re
from typing import Dict, List, Any

class EagleImplementer:
    """EAGLE - The Code Generation Beast"""
    
    def __init__(self):
        self.stage_name = "EAGLE"
        self.icon = "🦅"
        self.specialty = "Code Implementation & Generation"
        self.optimal_model = "llama-3.1-8b-instant"  # Code generation beast
    
    def implement_code(self, falcon_architecture: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main EAGLE function - generate working code based on FALCON architecture
        """
        print(f"🦅 EAGLE IMPLEMENTER: Generating working code...")
        
        # Extract architecture data
        architecture_text = falcon_architecture.get("raw_design", "")
        architecture_data = falcon_architecture.get("json_data", {})
        
        # Generate the EAGLE implementation prompt
        eagle_prompt = self._build_eagle_prompt(architecture_data)
        
        # Package the implementation for MCP processing
        eagle_implementation = {
            "stage": "EAGLE",
            "prompt": eagle_prompt,
            "falcon_input": falcon_architecture,
            "model": self.optimal_model,
            "temperature": 0.2,  # Lower for more consistent code
            "max_tokens": 2048,  # More tokens for code generation
            "implementation_type": "code_generation"
        }
        
        return eagle_implementation
    
    def _build_eagle_prompt(self, falcon_design: Dict[str, Any]) -> str:
        """Build the implementation prompt for EAGLE"""
        
        architecture = falcon_design.get("raw_design", "")
        tech_stack = falcon_design.get("json_data", {}).get("tech_stack", {})
        
        return f"""<thinking>
I need to implement the actual code based on this architecture design.

Architecture:
{architecture}

I should:
1. Write clean, well-documented code
2. Follow best practices for the chosen tech stack
3. Include necessary imports and dependencies
4. Add comments explaining complex logic
5. Structure the code for maintainability
</thinking>

Act as Eagle, a senior software engineer. Implement the code for this project.

Architecture:
{architecture}

Provide the implementation in this EXACT format:

**OVERVIEW:**
[Brief overview of implementation approach]

**TECH STACK:**
- Frontend: {tech_stack.get('frontend', 'Not specified')}
- Backend: {tech_stack.get('backend', 'Not specified')}
- Database: {tech_stack.get('database', 'Not specified')}

**IMPLEMENTATION DETAILS:**
[Explain key implementation decisions and considerations]

**CODE FILES:**

**filename: [filename]**
```[language]
[code content]
```

[Repeat for each file]

**TESTING INSTRUCTIONS:**
[How to test the implementation]


Then provide the structured data as JSON:
```json
{{
    "files_created": ["list of filenames"],
    "dependencies": ["list of required dependencies"],
    "complexity": "simple|moderate|complex",
    "confidence_score": 8
}}
```

Focus on production-quality, maintainable code."""
    
    def validate_eagle_response(self, response_text: str) -> Dict[str, Any]:
        """Validate that EAGLE response contains working code"""
        
        validation_result = {
            "valid": False,
            "has_overview": False,
            "has_code_files": False,
            "has_implementation_notes": False,
            "has_json": False,
            "file_count": 0,
            "character_count": len(response_text),
            "quality_score": 0
        }
        
        # Check for implementation overview
        if "IMPLEMENTATION OVERVIEW:" in response_text:
            validation_result["has_overview"] = True
            validation_result["quality_score"] += 1
        
        # Check for code files
        code_files = re.findall(r'```filename:\s*([^\n]+)\n(.*?)\n```', response_text, re.DOTALL)
        if code_files:
            validation_result["has_code_files"] = True
            validation_result["file_count"] = len(code_files)
            validation_result["quality_score"] += min(len(code_files), 3)  # Max 3 points for files
        
        # Check for implementation notes
        if "IMPLEMENTATION NOTES:" in response_text:
            validation_result["has_implementation_notes"] = True
            validation_result["quality_score"] += 1
        
        # Check for JSON data
        json_pattern = r'```json\s*\n(.*?)\n```'
        json_match = re.search(json_pattern, response_text, re.DOTALL)
        if json_match:
            try:
                json.loads(json_match.group(1))
                validation_result["has_json"] = True
                validation_result["quality_score"] += 2
            except json.JSONDecodeError:
                pass
        
        # Determine if valid
        validation_result["valid"] = (
            validation_result["has_code_files"] and 
            validation_result["file_count"] >= 1 and
            validation_result["character_count"] > 500
        )
        
        return validation_result
    
    def extract_code_files(self, response_text: str) -> List[Dict[str, Any]]:
        """Extract all code files from EAGLE response"""
        
        code_files = []
        
        # Pattern for filename-based code blocks
        filename_pattern = r'```filename:\s*([^\n]+)\n(.*?)\n```'
        filename_matches = re.findall(filename_pattern, response_text, re.DOTALL)
        
        for filename, code in filename_matches:
            file_data = {
                "filename": filename.strip(),
                "code": code.strip(),
                "language": self._detect_language(filename.strip()),
                "size": len(code.strip()),
                "lines": len(code.strip().split('\n'))
            }
            code_files.append(file_data)
        
        return code_files
    
    def extract_implementation_data(self, response_text: str) -> Dict[str, Any]:
        """Extract structured implementation data from EAGLE response"""
        
        implementation = {
            "overview": "",
            "code_files": [],
            "implementation_notes": [],
            "testing_instructions": [],
            "json_data": {},
            "raw_implementation": response_text
        }

        
        # Extract implementation overview
        overview_match = re.search(r'\*\*OVERVIEW:\*\*\s*\n([^\n*]+(?:\n[^\n*]+)*)', response_text)
        if overview_match:
            implementation["overview"] = overview_match.group(1).strip()
        
        # Extract code files
        implementation["code_files"] = self.extract_code_files(response_text)
        
        # Extract implementation notes
        notes_section = re.search(r'\*\*IMPLEMENTATION DETAILS:\*\*\s*\n((?:[^\n]+\n?)+)', response_text)
        if notes_section:
            notes = re.findall(r'[^\n]+', notes_section.group(1))
            implementation["implementation_notes"] = [note.strip() for note in notes]
        
        # Extract testing instructions
        test_section = re.search(r'\*\*TESTING INSTRUCTIONS:\*\*\s*\n((?:[^\n]+\n?)+)', response_text)
        if test_section:
            instructions = re.findall(r'[^\n]+', test_section.group(1))
            implementation["testing_instructions"] = [instruction.strip() for instruction in instructions]
        
        # Extract JSON data
        json_pattern = r'```json\s*\n(.*?)\n```'
        json_match = re.search(json_pattern, response_text, re.DOTALL)
        if json_match:
            try:
                implementation["json_data"] = json.loads(json_match.group(1))
            except json.JSONDecodeError:
                implementation["json_data"] = {}
        
        return implementation
    
    def _detect_language(self, filename: str) -> str:
        """Detect programming language from filename"""
        ext_map = {
            '.html': 'html',
            '.css': 'css', 
            '.js': 'javascript',
            '.py': 'python',
            '.java': 'java',
            '.cpp': 'cpp',
            '.c': 'c',
            '.php': 'php',
            '.rb': 'ruby',
            '.go': 'go',
            '.rs': 'rust',
            '.ts': 'typescript',
            '.jsx': 'jsx',
            '.tsx': 'tsx'
        }
        
        for ext, lang in ext_map.items():
            if filename.lower().endswith(ext):
                return lang
        
        return 'text'
    
    def generate_project_structure(self, code_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate project structure and file organization"""
        
        structure = {
            "total_files": len(code_files),
            "total_lines": sum(file_data["lines"] for file_data in code_files),
            "total_size": sum(file_data["size"] for file_data in code_files),
            "languages": list(set(file_data["language"] for file_data in code_files)),
            "file_breakdown": {}
        }
        
        # Categorize files by type
        for file_data in code_files:
            lang = file_data["language"]
            if lang not in structure["file_breakdown"]:
                structure["file_breakdown"][lang] = {
                    "count": 0,
                    "total_lines": 0,
                    "files": []
                }
            
            structure["file_breakdown"][lang]["count"] += 1
            structure["file_breakdown"][lang]["total_lines"] += file_data["lines"]
            structure["file_breakdown"][lang]["files"].append(file_data["filename"])
        
        return structure
    
    def optimize_code_structure(self, implementation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize code structure for better organization"""
        
        optimization_suggestions = {
            "structure_improvements": [],
            "performance_tips": [],
            "maintainability_suggestions": [],
            "scalability_considerations": []
        }
        
        code_files = implementation_data.get("code_files", [])

        
        # Analyze structure
        if len(code_files) > 5:
            optimization_suggestions["structure_improvements"].append(
                "Consider organizing files into folders (src/, assets/, components/)"
            )
        
        # Check for large files
        for file_data in code_files:
            if file_data["lines"] > 200:
                optimization_suggestions["maintainability_suggestions"].append(
                    f"Consider breaking down {file_data['filename']} - {file_data['lines']} lines is quite large"
                )
        
        # Performance suggestions based on file types
        languages = [file_data["language"] for file_data in code_files]
        if "javascript" in languages:
            optimization_suggestions["performance_tips"].extend([
                "Consider code splitting for large JavaScript files",
                "Implement lazy loading for better performance",
                "Minify JavaScript for production"
            ])
        
        if "css" in languages:
            optimization_suggestions["performance_tips"].extend([
                "Consider CSS minification and compression",
                "Use CSS custom properties for better maintainability"
            ])
        
        # Scalability considerations
        if len(code_files) >= 3:
            optimization_suggestions["scalability_considerations"].extend([
                "Consider implementing a build system (webpack, vite, etc.)",
                "Set up testing framework for future development",
                "Consider version control and deployment strategy"
            ])
        
        return optimization_suggestions

# Factory function for EAGLE bird
def create_eagle_implementer() -> EagleImplementer:
    """Factory function to create EAGLE implementer instance"""
    return EagleImplementer()

# Test function for EAGLE bird
def test_eagle_bird():
    """Test the EAGLE bird with sample FALCON input"""
    eagle = create_eagle_implementer()
    
    # Mock FALCON architecture
    falcon_architecture = {
        "raw_design": """
TECHNOLOGY STACK:
- Frontend: HTML, CSS, JavaScript
- Backend: None (client-side only)
- Database: LocalStorage

CORE COMPONENTS:
1. Game Engine - Handles snake movement and collision detection
2. Renderer - Draws game elements on canvas
3. Input Handler - Processes user keyboard input

FILE STRUCTURE:
```
snake_game/
├── index.html
├── styles.css
└── script.js
```
        """,
        "json_data": {
            "tech_stack": {
                "frontend": "HTML, CSS, JavaScript",
                "backend": "None",
                "database": "LocalStorage"
            },
            "complexity": "simple"
        }
    }
    
    implementation = eagle.implement_code(falcon_architecture)
    
    print("🧪 TESTING EAGLE BIRD")
    print(f"🦅 Stage: {implementation['stage']}")
    print(f"🤖 Model: {implementation['model']}")
    print(f"💻 Implementation Type: {implementation['implementation_type']}")
    print(f"📏 Prompt Length: {len(implementation['prompt'])} characters")
    print(f"🔥 Temperature: {implementation['temperature']}")
    print(f"📊 Max Tokens: {implementation['max_tokens']}")
    
    return implementation

if __name__ == "__main__":
    # Test EAGLE bird independently
    test_eagle_bird()
