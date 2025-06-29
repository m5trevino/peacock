
#!/usr/bin/env python3
"""
falcon.py - FALCON Architecture Design Bird
The senior architect who designs technical systems and component structures
"""

import json
import re
from typing import Dict, List, Any

class FalconArchitect:
    """FALCON - The System Architect"""
    
    def __init__(self):
        self.stage_name = "FALCON"
        self.icon = "🦅"
        self.specialty = "Technical Architecture Design"
        self.optimal_model = "gemma2-9b-it"  # Structure champion
    
    def design_architecture(self, spark_requirements: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate architecture design prompt based on SPARK requirements.
        MCP will handle the actual LLM call.
        """
        print(f"🦅 FALCON ARCHITECT: Generating architecture design prompt...")
        
        # Extract key data from SPARK analysis
        spark_analysis = spark_requirements.get("analysis", {})
        spark_text = spark_requirements.get("raw_response", "")
        
        if not spark_text and isinstance(spark_analysis, dict):
            spark_text = "\n".join(f"{k}: {v}" for k, v in spark_analysis.items())
        
        # Generate the FALCON architecture prompt
        falcon_prompt = self._build_falcon_prompt(spark_text, spark_analysis)
        
        # Package the prompt for MCP processing
        falcon_design = {
            "stage": "FALCON",
            "prompt": falcon_prompt,
            "spark_input": spark_requirements,
            "model": self.optimal_model,
            "temperature": 0.3,
            "max_tokens": 1024,
            "design_type": "technical_architecture"
        }
        
        print(f"✅ FALCON prompt generated: {len(falcon_prompt)} characters")
        return falcon_design
    
    def _build_falcon_prompt(self, spark_text: str, requirements_data: Dict[str, Any]) -> str:
        """Build the technical architecture design prompt"""
        
        return f"""<thinking>
Based on the requirements from Spark, I need to design a technical architecture.

Requirements: {spark_text}

I should think about:
- What technologies would work best
- How to structure the codebase
- What components are needed
- How they interact
</thinking>

Act as Falcon, a senior software architect. Design the technical architecture for this project.

Requirements Analysis:
{spark_text}

Provide architecture design in this EXACT format:


**TECHNOLOGY STACK:**
- Frontend: [Technology choices]
- Backend: [Technology choices]  
- Database: [Technology choices]
- Additional: [Other technologies]

**CORE COMPONENTS:**
1. [Component Name] - [Purpose and functionality]
2. [Component Name] - [Purpose and functionality]
3. [Component Name] - [Purpose and functionality]

**FILE STRUCTURE:**
```
project_root/
├── [folder1]/
│   ├── [file1.ext]
│   └── [file2.ext]
├── [folder2]/
└── [file3.ext]
```

**COMPONENT INTERACTIONS:**
[Describe how components communicate and data flows]

Then provide the structured data as JSON:
```json
{{
    "tech_stack": {{
        "frontend": "string",
        "backend": "string",
        "database": "string"
    }},
    "components": ["list"],
    "complexity": "simple|moderate|complex",
    "file_structure": ["list"],
    "interactions": "string"
}}
"""
        
    def validate_falcon_response(self, response_text: str) -> Dict[str, Any]:
        """Validate that FALCON response contains required architecture elements"""
        
        validation_result = {
            "valid": False,
            "has_tech_stack": False,
            "has_components": False,
            "has_file_structure": False,
            "has_json": False,
            "character_count": len(response_text),
            "quality_score": 0
        }
        
        # Check for technology stack
        if "TECHNOLOGY STACK:" in response_text:
            validation_result["has_tech_stack"] = True
            validation_result["quality_score"] += 2
        
        # Check for core components
        if "CORE COMPONENTS:" in response_text:
            validation_result["has_components"] = True
            validation_result["quality_score"] += 2
        
        # Check for file structure
        if "FILE STRUCTURE:" in response_text and "project_root/" in response_text:
            validation_result["has_file_structure"] = True
            validation_result["quality_score"] += 2
        
        # Check for JSON data
        json_pattern = r'```json\s*\n(.*?)\n```'
        json_match = re.search(json_pattern, response_text, re.DOTALL)
        if json_match:
            try:

                json.loads(json_match.group(1))
                validation_result["has_json"] = True
                validation_result["quality_score"] += 3
            except json.JSONDecodeError:
                pass
        
        # Determine if valid
        validation_result["valid"] = (
            validation_result["has_tech_stack"] and 
            validation_result["has_components"] and
            validation_result["character_count"] > 300
        )
        
        return validation_result
    
    def extract_architecture_data(self, response_text: str) -> Dict[str, Any]:
        """Extract structured architecture data from FALCON response"""
        
        architecture = {
            "tech_stack": {},
            "components": [],
            "file_structure": "",
            "component_interactions": "",
            "json_data": {},
            "raw_design": response_text
        }
        
        # Extract technology stack
        tech_section = re.search(r'\*\*TECHNOLOGY STACK:\*\*\s*\n((?:- [^\n]+\n?)+)', response_text)
        if tech_section:
            tech_items = re.findall(r'- ([^:]+): ([^\n]+)', tech_section.group(1))
            for category, tech in tech_items:
                architecture["tech_stack"][category.strip().lower()] = tech.strip()
        
        # Extract core components
        comp_section = re.search(r'\*\*CORE COMPONENTS:\*\*\s*\n((?:\d+\. [^\n]+\n?)+)', response_text)
        if comp_section:
            components = re.findall(r'\d+\. ([^-]+) - ([^\n]+)', comp_section.group(1))
            for name, purpose in components:
                architecture["components"].append({
                    "name": name.strip(),
                    "purpose": purpose.strip()
                })
        
        # Extract file structure
        file_match = re.search(r'\*\*FILE STRUCTURE:\*\*\s*\n```\s*\n(.*?)\n```', response_text, re.DOTALL)
        if file_match:
            architecture["file_structure"] = file_match.group(1).strip()
        
        # Extract component interactions
        interact_match = re.search(r'\*\*COMPONENT INTERACTIONS:\*\*\s*\n([^\n*]+(?:\n[^\n*]+)*)', response_text)
        if interact_match:
            architecture["component_interactions"] = interact_match.group(1).strip()
        
        # Extract JSON data
        json_pattern = r'```json\s*\n(.*?)\n```'
        json_match = re.search(json_pattern, response_text, re.DOTALL)
        if json_match:
            try:
                architecture["json_data"] = json.loads(json_match.group(1))
            except json.JSONDecodeError:
                architecture["json_data"] = {}
        
        return architecture
    
    def generate_component_specs(self, architecture_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate detailed specifications for each component"""
        
        component_specs = []
        
        for component in architecture_data.get("components", []):
            spec = {

                "name": component["name"],
                "purpose": component["purpose"],
                "technologies": self._suggest_technologies_for_component(component["name"]),
                "interfaces": self._define_component_interfaces(component["name"]),
                "dependencies": self._identify_dependencies(component["name"], architecture_data)
            }
            component_specs.append(spec)
        
        return component_specs
    
    def _suggest_technologies_for_component(self, component_name: str) -> List[str]:
        """Suggest appropriate technologies for a component"""
        name_lower = component_name.lower()
        
        if any(term in name_lower for term in ['ui', 'interface', 'frontend', 'view']):
            return ['HTML', 'CSS', 'JavaScript']
        elif any(term in name_lower for term in ['api', 'server', 'backend', 'service']):
            return ['Python', 'Node.js', 'Express']
        elif any(term in name_lower for term in ['database', 'storage', 'data']):
            return ['SQLite', 'PostgreSQL', 'MongoDB']
        elif any(term in name_lower for term in ['auth', 'security', 'login']):
            return ['JWT', 'OAuth', 'bcrypt']
        else:
            return ['JavaScript', 'Python']
    
    def _define_component_interfaces(self, component_name: str) -> Dict[str, List[str]]:
        """Define interfaces for component communication"""
        return {
            "inputs": ["data", "user_actions", "events"],
            "outputs": ["responses", "updates", "notifications"],
            "methods": ["initialize", "process", "validate", "cleanup"]
        }
    
    def _identify_dependencies(self, component_name: str, architecture_data: Dict[str, Any]) -> List[str]:
        """Identify dependencies between components"""
        all_components = [comp["name"] for comp in architecture_data.get("components", [])]
        # Simple dependency logic - can be enhanced
        return [comp for comp in all_components if comp != component_name]

# Factory function for FALCON bird
def create_falcon_architect() -> FalconArchitect:
    """Factory function to create FALCON architect instance"""
    return FalconArchitect()

# Test function for FALCON bird
def test_falcon_bird():
    """Test the FALCON bird with sample SPARK input"""
    falcon = create_falcon_architect()
    
    # Mock SPARK requirements
    spark_requirements = {
        "raw_response": "Build a snake game with HTML, CSS, and JavaScript",
        "analysis": {
            "core_objective": "Create an interactive snake game",
            "in_scope": ["Game mechanics", "Score tracking", "Visual interface"],
            "complexity": "simple"
        }
    }
    
    design = falcon.design_architecture(spark_requirements)
    
    print("🧪 TESTING FALCON BIRD")
    print(f"🦅 Stage: {design['stage']}")
    print(f"🤖 Model: {design['model']}")
    print(f"🏗️ Design Type: {design['design_type']}")
    print(f"📏 Prompt Length: {len(design['prompt'])} characters")
    
    return design

if __name__ == "__main__":
    # Test FALCON bird independently
    test_falcon_bird()
