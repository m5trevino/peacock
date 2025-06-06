# PEACOCK → MCP → GROQ LLM2 COMPLETE BRIDGE
# This handles the full handoff from Spark analysis to working files

import requests
import json
import os
from groq import Groq
from pathlib import Path
import time

class PeacockMCPGroqBridge:
    def __init__(self):
        self.mcp_url = "http://127.0.0.1:8000"
        self.groq_client = None
        self.setup_groq()
        
    def setup_groq(self):
        """Initialize Groq client with API key"""
        groq_api_key = os.getenv('GROQ_API_KEY')
        if not groq_api_key:
            print("❌ GROQ_API_KEY not found in environment")
            print("💡 Set it with: export GROQ_API_KEY='your_key_here'")
            return False
            
        self.groq_client = Groq(api_key=groq_api_key)
        print("✅ Groq client initialized")
        return True
        
    def send_to_enhanced_mcp(self, spark_response, user_request, stage="spark_analysis"):
        """Send Spark analysis to Enhanced MCP for processing"""
        print(f"🔄 Sending to Enhanced MCP (stage: {stage})")
        
        mcp_payload = {
            "command": stage,
            "text": spark_response,
            "project_request": user_request,
            "language": "project_analysis",
            "timestamp": int(time.time())
        }
        
        try:
            response = requests.post(
                f"{self.mcp_url}/process", 
                json=mcp_payload,
                timeout=30
            )
            
            if response.status_code == 200:
                print("✅ MCP processing successful")
                return response.json()
            else:
                print(f"❌ MCP error: {response.status_code}")
                print(f"Response: {response.text}")
                return None
                
        except requests.exceptions.ConnectionError:
            print("❌ Can't connect to Enhanced MCP server")
            print("💡 Make sure Enhanced MCP is running on port 8000")
            return None
        except Exception as e:
            print(f"❌ MCP connection error: {e}")
            return None
            
    def send_to_groq_llm2(self, mcp_structured_output, model="llama3-8b-8192"):
        """Send structured MCP output to Groq LLM2 for code generation"""
        if not self.groq_client:
            print("❌ Groq client not initialized")
            return None
            
        print(f"🤖 Sending to Groq LLM2 (model: {model})")
        
        # Extract the structured content from MCP
        if isinstance(mcp_structured_output, dict):
            structured_prompt = mcp_structured_output.get('structured_output', mcp_structured_output)
        else:
            structured_prompt = mcp_structured_output
            
        # Build the LLM2 prompt for code generation
        llm2_prompt = f"""You are LLM2 - the code generation specialist.

You receive structured project specifications and generate complete, working code.

STRUCTURED INPUT FROM MCP:
{json.dumps(structured_prompt, indent=2)}

INSTRUCTIONS:
1. Generate complete, working code based on the structured specifications
2. Include all necessary files, dependencies, and configurations
3. Provide clear file structure and implementation
4. Include error handling and proper documentation
5. Make it production-ready, not just a prototype

OUTPUT FORMAT:
Provide the complete code implementation with clear file separations using this format:

```filename: path/to/file.ext
[complete file content]
```

Begin code generation now:"""

        try:
            completion = self.groq_client.chat.completions.create(
                messages=[
                    {
                        "role": "system", 
                        "content": "You are a code generation specialist. Generate complete, working implementations."
                    },
                    {
                        "role": "user",
                        "content": llm2_prompt
                    }
                ],
                model=model,
                temperature=0.1,
                max_tokens=8192
            )
            
            response_content = completion.choices[0].message.content
            print("✅ Groq LLM2 code generation complete")
            return response_content
            
        except Exception as e:
            print(f"❌ Groq API error: {e}")
            return None
            
    def process_llm2_output_to_files(self, llm2_response, project_name="peacock_project"):
        """Convert LLM2 response into actual files on disk"""
        if not llm2_response:
            print("❌ No LLM2 response to process")
            return None
            
        print("📁 Converting LLM2 output to files")
        
        # Create project directory
        project_dir = Path(project_name)
        project_dir.mkdir(exist_ok=True)
        
        # Parse the LLM2 response for file blocks
        files_created = []
        current_file = None
        current_content = []
        
        lines = llm2_response.split('\n')
        
        for line in lines:
            # Look for file markers: ```filename: path/to/file.ext
            if line.startswith('```filename:'):
                # Save previous file if exists
                if current_file and current_content:
                    self.save_file(project_dir, current_file, '\n'.join(current_content))
                    files_created.append(current_file)
                
                # Start new file
                current_file = line.replace('```filename:', '').strip()
                current_content = []
                
            elif line.startswith('```') and current_file:
                # End of file block
                if current_content:
                    self.save_file(project_dir, current_file, '\n'.join(current_content))
                    files_created.append(current_file)
                current_file = None
                current_content = []
                
            elif current_file:
                # Add line to current file content
                current_content.append(line)
        
        # Save final file if exists
        if current_file and current_content:
            self.save_file(project_dir, current_file, '\n'.join(current_content))
            files_created.append(current_file)
            
        print(f"✅ Created {len(files_created)} files in {project_dir}")
        for file_path in files_created:
            print(f"   📄 {file_path}")
            
        return {
            "project_dir": str(project_dir),
            "files_created": files_created,
            "total_files": len(files_created)
        }
        
    def save_file(self, project_dir, file_path, content):
        """Save individual file with proper directory structure"""
        full_path = project_dir / file_path
        
        # Create directories if needed
        full_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write file content
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)
            
    def complete_pipeline(self, spark_response, user_request, project_name=None):
        """Execute the complete Spark → MCP → Groq → Files pipeline"""
        print("🚀 Starting complete Peacock pipeline")
        print("=" * 50)
        
        # Generate project name if not provided
        if not project_name:
            project_name = f"peacock_project_{int(time.time())}"
            
        # Step 1: Send to Enhanced MCP
        print("\n🔄 Step 1: Processing through Enhanced MCP")
        mcp_result = self.send_to_enhanced_mcp(spark_response, user_request)
        
        if not mcp_result:
            print("❌ Pipeline failed at MCP stage")
            return None
            
        # Step 2: Send to Groq LLM2
        print("\n🤖 Step 2: Generating code with Groq LLM2")
        llm2_code = self.send_to_groq_llm2(mcp_result)
        
        if not llm2_code:
            print("❌ Pipeline failed at Groq LLM2 stage")
            return None
            
        # Step 3: Convert to files
        print("\n📁 Step 3: Creating project files")
        file_result = self.process_llm2_output_to_files(llm2_code, project_name)
        
        if file_result:
            print("\n🎉 PIPELINE COMPLETE!")
            print(f"📦 Project created: {file_result['project_dir']}")
            print(f"📄 Files generated: {file_result['total_files']}")
            return file_result
        else:
            print("❌ Pipeline failed at file creation stage")
            return None

# ENHANCED PEACOCK MODEL SELECTOR INTEGRATION
class EnhancedPeacockModelSelector:
    """Extended version of peacock_model_selector.py with MCP/Groq integration"""
    
    def __init__(self):
        # Import the existing peacock_model_selector functionality
        from peacock_model_selector import PeacockModelSelector
        self.base_selector = PeacockModelSelector()
        self.bridge = PeacockMCPGroqBridge()
        
    def run_complete_pipeline(self, user_request, project_name=None):
        """Run the complete pipeline: Human → Spark → MCP → Groq → Files"""
        print("🦚 PEACOCK COMPLETE PIPELINE STARTING")
        print("=" * 60)
        
        # Step 1: Get Spark analysis using existing model selector
        print("\n⚡ Step 1: Spark Requirements Analysis")
        provider, model = self.base_selector.select_model_interactive()
        spark_response = self.base_selector.send_initial_prompt(provider, model, user_request)
        
        if not spark_response:
            print("❌ Failed to get Spark analysis")
            return None
            
        print("✅ Spark analysis complete")
        print(f"📝 Response length: {len(spark_response)} characters")
        
        # Step 2-4: Run the complete MCP → Groq → Files pipeline
        return self.bridge.complete_pipeline(spark_response, user_request, project_name)

# MAIN EXECUTION SCRIPT
if __name__ == "__main__":
    import sys
    
    print("🦚 PEACOCK COMPLETE PIPELINE")
    print("=" * 40)
    
    # Get user request
    if len(sys.argv) > 1:
        user_request = " ".join(sys.argv[1:])
    else:
        user_request = input("🎯 What do you want to build? ")
        
    if not user_request.strip():
        print("❌ No project request provided")
        sys.exit(1)
        
    # Get optional project name
    project_name = input("📦 Project name (press Enter for auto-generated): ").strip()
    if not project_name:
        project_name = None
        
    # Run complete pipeline
    enhanced_selector = EnhancedPeacockModelSelector()
    result = enhanced_selector.run_complete_pipeline(user_request, project_name)
    
    if result:
        print("\n🎉 SUCCESS! Your project is ready:")
        print(f"📁 Location: {result['project_dir']}")
        print(f"📄 Files: {result['total_files']}")
        print("\nYour Peacock pipeline is working perfectly! 🔥")
    else:
        print("\n❌ Pipeline failed. Check the steps above for errors.")
        
    print("\n🦚 Peacock Complete Pipeline Finished")
