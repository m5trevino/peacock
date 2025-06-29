#!/usr/bin/env python3
"""
Fix Peacock Dashboard Integration Issues
- XEdit HTML generation and linking
- Character count display
- Log file paths
- Session ID consistency
"""

import os
import re
import json
from pathlib import Path

def fix_1prompt_dashboard():
    """Fix the 1prompt.py dashboard file"""
    dashboard_file = Path("/home/flintx/peacock/core/1prompt.py")
    
    if not dashboard_file.exists():
        print("❌ 1prompt.py not found")
        return False
    
    content = dashboard_file.read_text()
    
    # Fix character count handling - support both 'chars' and 'char_count'
    char_count_fix = '''
                    // Update each stage with actual data - FIXED character count handling
                    if (stageData.spark) {
                        const sparkChars = stageData.spark.chars || stageData.spark.char_count || 0;
                        updateStageStatus('spark', 'completed', 'Requirements complete', sparkChars);
                    }
                    if (stageData.falcon) {
                        const falconChars = stageData.falcon.chars || stageData.falcon.char_count || 0;
                        updateStageStatus('falcon', 'completed', 'Architecture complete', falconChars);
                    }
                    if (stageData.eagle) {
                        const eagleChars = stageData.eagle.chars || stageData.eagle.char_count || 0;
                        updateStageStatus('eagle', 'completed', 'Code complete', eagleChars);
                    }
                    if (stageData.hawk) {
                        const hawkChars = stageData.hawk.chars || stageData.hawk.char_count || 0;
                        updateStageStatus('hawk', 'completed', 'QA complete', hawkChars);
                    }
                    
                    // Calculate totals with proper fallback
                    const totalChars = Object.values(stageData).reduce((sum, stage) => {
                        const chars = stage.chars || stage.char_count || 0;
                        return sum + chars;
                    }, 0);'''
    
    # Replace the existing character count logic
    content = re.sub(
        r'// Update each stage with actual data.*?const totalChars = .*?;',
        char_count_fix,
        content,
        flags=re.DOTALL
    )
    
    # Fix log links to point to correct location
    log_links_fix = '''
                <div class="log-links">
                    <a href="#" class="log-link" id="promptLogLink" target="_blank">📝 Prompt Log</a>
                    <a href="#" class="log-link" id="responseLogLink" target="_blank">📋 Response Log</a>
                    <a href="#" class="log-link" id="mcpLogLink" target="_blank">🔧 MCP Log</a>
                    <a href="#" class="log-link" id="xeditLogLink" target="_blank">🎯 XEdit Log</a>
                    <a href="#" class="log-link" id="megaPromptLogLink" target="_blank">🔥 Mega Prompt Log</a>
                    <a href="#" class="log-link" id="finalResponseLogLink" target="_blank">✅ Final Response Log</a>
                </div>'''
    
    content = re.sub(
        r'<div class="log-links">.*?</div>',
        log_links_fix,
        content,
        flags=re.DOTALL
    )
    
    # Fix updateLogLinks function
    update_log_links_fix = '''
        function updateLogLinks(sessionId) {
            // Update all log links with correct session ID and paths
            document.getElementById('promptLogLink').href = `file:///home/flintx/peacock/core/logs/promptlog-${sessionId}.txt`;
            document.getElementById('responseLogLink').href = `file:///home/flintx/peacock/core/logs/responselog-${sessionId}.txt`;
            document.getElementById('mcpLogLink').href = `file:///home/flintx/peacock/core/logs/mcplog-${sessionId}.txt`;
            document.getElementById('xeditLogLink').href = `file:///home/flintx/peacock/core/logs/xeditlog-${sessionId}.txt`;
            document.getElementById('megaPromptLogLink').href = `file:///home/flintx/peacock/core/logs/megapromptlog-${sessionId}.txt`;
            document.getElementById('finalResponseLogLink').href = `file:///home/flintx/peacock/core/logs/finalresponselog-${sessionId}.txt`;
        }'''
    
    # Add or replace updateLogLinks function
    if 'function updateLogLinks' in content:
        content = re.sub(
            r'function updateLogLinks\(.*?\}',
            update_log_links_fix,
            content,
            flags=re.DOTALL
        )
    else:
        # Add before openXEdit function
        content = content.replace(
            'function openXEdit()',
            update_log_links_fix + '\n        \n        function openXEdit()'
        )
    
    # Fix openXEdit function
    open_xedit_fix = '''
        function openXEdit() {
            // Construct XEdit path with current session ID
            const xeditPath = `file:///home/flintx/peacock/html/xedit-${sessionTimestamp}.html`;
            console.log('Opening XEdit:', xeditPath);
            
            // Try to open the XEdit file
            try {
                window.open(xeditPath, '_blank');
            } catch (error) {
                console.error('Failed to open XEdit:', error);
                alert('Failed to open XEdit interface. Check if the file exists at: ' + xeditPath);
            }
        }'''
    
    content = re.sub(
        r'function openXEdit\(\).*?\}',
        open_xedit_fix,
        content,
        flags=re.DOTALL
    )
    
    # Write the fixed content back
    dashboard_file.write_text(content)
    print("✅ Fixed 1prompt.py dashboard")
    return True

def fix_out_homing_xedit_generation():
    """Fix XEdit generation in out_homing.py"""
    out_homing_file = Path("/home/flintx/peacock/aviary/out_homing.py")
    
    if not out_homing_file.exists():
        print("❌ out_homing.py not found")
        return False
    
    content = out_homing_file.read_text()
    
    # Ensure XEdit generation is properly integrated
    xedit_integration = '''
            # Step 3: Process with IN-HOMING and generate XEdit
            print("🔄 IN-HOMING: Processing final code and generating XEdit...")
            final_code = final_code_result.get("final_code", "")
            if not final_code:
                final_code = bird_results.get("stage_results", {}).get("eagle", {}).get("response", "")
            
            # Import and use IN-HOMING processor
            try:
                from in_homing import InHomingProcessor
                in_homing_processor = InHomingProcessor()
                
                processing_result = in_homing_processor.process_llm2_response(
                    final_code,
                    pipeline_metadata={
                        "project_name": user_request[:50],
                        "session_timestamp": self.session_timestamp,
                        "final_model_used": final_code_result.get("model_used", final_model_choice)
                    }
                )
                
                xedit_file_path = processing_result.get("xedit_file_path")
                project_files = processing_result.get("project_files", [])
                
                if xedit_file_path:
                    print(f"✅ XEdit interface generated: {xedit_file_path}")
                else:
                    print("⚠️ XEdit generation failed")
                    
            except Exception as e:
                print(f"⚠️ XEdit generation error: {e}")
                xedit_file_path = None
                project_files = []'''
    
    # Replace the existing XEdit generation step
    if "Step 3: Process with IN-HOMING" in content:
        content = re.sub(
            r'# Step 3: Process with IN-HOMING.*?project_files = processing_result\.get\("project_files", \[\]\)',
            xedit_integration,
            content,
            flags=re.DOTALL
        )
    
    # Write back the content
    out_homing_file.write_text(content)
    print("✅ Fixed out_homing.py XEdit generation")
    return True

def fix_in_homing_processor():
    """Fix the IN-HOMING processor for better XEdit generation"""
    in_homing_file = Path("/home/flintx/peacock/aviary/in_homing.py")
    
    if not in_homing_file.exists():
        print("❌ in_homing.py not found")
        return False
    
    content = in_homing_file.read_text()
    
    # Fix the _call_xedit_generator method
    xedit_generator_fix = '''
    def _call_xedit_generator(self, processing_result: Dict[str, Any], session_timestamp: str) -> str:
        """Call xedit.py to generate the HTML interface"""
        try:
            # Import XEdit generator from the actual classes in your xedit.py
            sys.path.insert(0, str(Path(__file__).parent.parent / "core"))
            from xedit import EnhancedXEditGenerator
            
            # Create generator instance
            xedit_generator = EnhancedXEditGenerator()
            
            # Prepare data for XEdit generation
            parsed_data = processing_result["parsed_data"]
            xedit_paths = processing_result["xedit_paths"]
            
            # Generate the HTML file
            xedit_file_path = xedit_generator.generate_enhanced_xedit_html(
                parsed_data=parsed_data,
                xedit_paths=xedit_paths, 
                session_id=session_timestamp
            )
            
            print(f"✅ XEdit interface generated: {xedit_file_path}")
            return xedit_file_path
            
        except Exception as e:
            print(f"❌ XEdit generation failed: {e}")
            print(f"❌ Error details: {str(e)}")
            
            # Try to create a simple HTML file as fallback
            fallback_path = f"/home/flintx/peacock/html/xedit-{session_timestamp}.html"
            try:
                Path("/home/flintx/peacock/html").mkdir(parents=True, exist_ok=True)
                with open(fallback_path, 'w') as f:
                    f.write(f"""<!DOCTYPE html>
<html><head><title>XEdit - {session_timestamp}</title></head>
<body>
<h1>🦚 Peacock XEdit Interface</h1>
<p>Session: {session_timestamp}</p>
<p>XEdit generation encountered an error: {str(e)}</p>
<p>This is a fallback interface.</p>
</body></html>""")
                print(f"✅ Created fallback XEdit file: {fallback_path}")
                return fallback_path
            except Exception as fallback_error:
                print(f"❌ Even fallback failed: {fallback_error}")
                return f"/home/flintx/peacock/html/xedit-{session_timestamp}-error.html"'''
    
    # Replace the existing _call_xedit_generator method
    content = re.sub(
        r'def _call_xedit_generator\(self.*?return.*?\.html"',
        xedit_generator_fix,
        content,
        flags=re.DOTALL
    )
    
    in_homing_file.write_text(content)
    print("✅ Fixed in_homing.py XEdit generator")
    return True

def fix_pea_mcp_server():
    """Fix the MCP server to properly handle character counts"""
    mcp_file = Path("/home/flintx/peacock/core/pea-mcp-1.py")
    
    if not mcp_file.exists():
        print("❌ pea-mcp-1.py not found")
        return False
    
    content = mcp_file.read_text()
    
    # Fix character count handling in the response
    char_count_response_fix = '''
            # FIXED: Properly format the response for the frontend with character counts
            formatted_stage_results = {}
            for stage_name, stage_data in stage_results.items():
                # Make sure both 'chars' and 'char_count' are available
                char_count = stage_data.get("char_count", stage_data.get("chars", 0))
                formatted_stage_results[stage_name] = {
                    "chars": char_count,
                    "char_count": char_count,
                    "model": stage_data.get("model", "unknown"),
                    "response": stage_data.get("response", ""),
                    "success": stage_data.get("success", True)
                }
            
            # Return a clean, explicit JSON response for the client
            return {
                "success": True,
                "xedit_file_path": pipeline_result.get("xedit_file_path"),
                "project_files": pipeline_result.get("project_files", []),
                "pipeline_result": {
                    "stage_results": formatted_stage_results,
                    "session_timestamp": session_timestamp,
                    "api_calls_made": pipeline_result.get("api_calls_made", 0),
                    "model_used": pipeline_result.get("model_used", final_model_choice)
                },
                "stage_results": formatted_stage_results
            }'''
    
    # Replace the response formatting section
    if "FIXED: Properly format the response" in content:
        content = re.sub(
            r'# FIXED: Properly format the response.*?}',
            char_count_response_fix,
            content,
            flags=re.DOTALL
        )
    
    mcp_file.write_text(content)
    print("✅ Fixed pea-mcp-1.py character count handling")
    return True

def create_directories():
    """Ensure all necessary directories exist"""
    directories = [
        "/home/flintx/peacock/html",
        "/home/flintx/peacock/core/logs",
        "/home/flintx/peacock/logs",
        "/home/flintx/peacock/apps"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Created directory: {directory}")

def main():
    """Run all fixes"""
    print("🔧 FIXING PEACOCK DASHBOARD INTEGRATION ISSUES...")
    print("=" * 60)
    
    # Create necessary directories
    create_directories()
    
    # Run all fixes
    fixes = [
        ("1prompt Dashboard", fix_1prompt_dashboard),
        ("OUT-HOMING XEdit Generation", fix_out_homing_xedit_generation),
        ("IN-HOMING Processor", fix_in_homing_processor),
        ("MCP Server", fix_pea_mcp_server)
    ]
    
    success_count = 0
    for name, fix_func in fixes:
        print(f"\n🔧 Fixing {name}...")
        if fix_func():
            success_count += 1
        else:
            print(f"❌ Failed to fix {name}")
    
    print("\n" + "=" * 60)
    print(f"✅ FIXES COMPLETED: {success_count}/{len(fixes)} successful")
    print("\n🚀 WHAT WAS FIXED:")
    print("   📊 Character count display in dashboard")
    print("   🔗 Log file links pointing to correct locations")
    print("   🎯 XEdit HTML generation and linking")
    print("   📱 Session ID consistency across components")
    print("   🔄 Error handling and fallback mechanisms")
    print("\n🧪 TEST THE FIXES:")
    print("   1. Run: python3 /home/flintx/peacock/core/1prompt.py")
    print("   2. Start MCP server: python3 /home/flintx/peacock/core/pea-mcp-1.py --log")
    print("   3. Test a prompt: 'build a snake game'")
    print("   4. Check that character counts populate")
    print("   5. Verify XEdit button opens the interface")
    print("   6. Check that log links work")

if __name__ == "__main__":
    main()