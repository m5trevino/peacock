#!/bin/bash
# ADD THE MISSING MEGA PROMPT ASSEMBLY AND FINAL CODE GENERATION TO OUT_HOMING.PY
# PROPERLY USING ENVIRONMENT VARIABLES FROM .ENV FILE

echo "🔥 ADDING MEGA PROMPT ASSEMBLY AND FINAL CODE GENERATION..."

# STEP 1: Add the mega prompt assembly function to out_homing.py
cat >> /home/flintx/peacock/core/out_homing.py << 'EOF'

    def _assemble_mega_prompt(self, user_request: str, bird_results: Dict[str, Any]) -> str:
        """Assemble mega prompt from all 4 bird outputs"""
        
        # Get individual bird responses
        spark_response = bird_results.get("spark", {}).get("response", "")
        falcon_response = bird_results.get("falcon", {}).get("response", "")  
        eagle_response = bird_results.get("eagle", {}).get("response", "")
        hawk_response = bird_results.get("hawk", {}).get("response", "")
        
        # Assemble the mega prompt
        mega_prompt = f"""
COMPREHENSIVE PROJECT GENERATION REQUEST

ORIGINAL USER REQUEST: {user_request}

REQUIREMENTS ANALYSIS (SPARK):
{spark_response}

TECHNICAL ARCHITECTURE (FALCON):
{falcon_response}

IMPLEMENTATION DETAILS (EAGLE):
{eagle_response}

QUALITY ASSURANCE STRATEGY (HAWK):
{hawk_response}

FINAL INSTRUCTION:
Based on the above comprehensive analysis, generate COMPLETE, EXECUTABLE CODE FILES for "{user_request}".

CRITICAL OUTPUT FORMAT - YOU MUST RETURN EXACTLY THIS:

```filename: index.html
<!DOCTYPE html>
<html>
<head>
    <title>{user_request}</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    [COMPLETE HTML IMPLEMENTATION]
    <script src="script.js"></script>
</body>
</html>
```

```filename: style.css
[COMPLETE CSS STYLING FOR THE APPLICATION]
```

```filename: script.js
[COMPLETE JAVASCRIPT IMPLEMENTATION WITH ALL FUNCTIONS]
```

CRITICAL REQUIREMENTS:
- Return ONLY the code files in the exact format above
- NO documentation, explanations, or QA procedures
- All code must be complete and functional
- Include ALL necessary functions and styling
- Make it a fully working application

DO NOT RETURN ANYTHING EXCEPT THE CODE FILES.
"""
        
        return mega_prompt

    def _generate_final_code_with_mega_prompt(self, mega_prompt: str) -> Dict[str, Any]:
        """Send mega prompt to Groq and get final code generation"""
        
        print("🎯 ASSEMBLING MEGA PROMPT AND GENERATING FINAL CODE...")
        
        # Log the mega prompt
        self._log_mega_prompt(mega_prompt)
        
        try:
            # Get API key from environment variables
            from dotenv import load_dotenv
            import os
            load_dotenv()
            
            api_key = os.getenv("GROQ_API_KEY")
            if not api_key:
                print("⚠️ No GROQ_API_KEY found in environment variables")
                api_key = os.getenv("GROQ_API_KEY_1")  # Try alternate key name
            
            if not api_key:
                raise ValueError("No Groq API key found in environment variables")
                
            model = os.getenv("FINAL_MODEL", "meta-llama/llama-4-maverick-17b-128e-instruct")
            
            # Initialize Groq client
            from groq import Groq
            client = Groq(api_key=api_key)
            
            print(f"🔗 FINAL CODE GENERATION API call (model: {model})")
            
            # Make the final API call with mega prompt
            response = client.chat.completions.create(
                messages=[
                    {
                        "role": "user",
                        "content": mega_prompt
                    }
                ],
                model=model,
                max_tokens=4000,
                temperature=0.3
            )
            
            final_response = response.choices[0].message.content
            
            # Log the final response
            self._log_final_response(final_response, model)
            
            print(f"✅ FINAL CODE GENERATION Success - {len(final_response)} chars - Model: {model}")
            
            return {
                "success": True,
                "final_code": final_response,
                "model_used": model,
                "characters": len(final_response)
            }
            
        except Exception as e:
            print(f"❌ FINAL CODE GENERATION failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "final_code": ""
            }

    def _log_mega_prompt(self, mega_prompt: str):
        """Log the assembled mega prompt"""
        import os
        
        # Ensure logs directory exists
        logs_dir = "/home/flintx/peacock/core/logs"
        os.makedirs(logs_dir, exist_ok=True)
        
        # Write mega prompt log
        mega_log_path = f"{logs_dir}/megapromptlog-{self.session_timestamp}.txt"
        
        with open(mega_log_path, "w") as f:
            f.write(f"[{datetime.datetime.now().isoformat()}] ASSEMBLED MEGA PROMPT\n")
            f.write(f"Session: {self.session_timestamp}\n")
            f.write("=" * 60 + "\n")
            f.write("MEGA PROMPT CONTENT:\n")
            f.write("=" * 60 + "\n")
            f.write(mega_prompt)
            f.write("\n" + "=" * 60 + "\n")
        
        print(f"✅ Mega prompt logged: {mega_log_path}")

    def _log_final_response(self, final_response: str, model_used: str):
        """Log the final code generation response"""
        import os
        
        # Ensure logs directory exists
        logs_dir = "/home/flintx/peacock/core/logs"
        os.makedirs(logs_dir, exist_ok=True)
        
        # Write final response log
        final_log_path = f"{logs_dir}/finalresponselog-{self.session_timestamp}.txt"
        
        with open(final_log_path, "w") as f:
            f.write(f"[{datetime.datetime.now().isoformat()}] FINAL CODE GENERATION RESPONSE\n")
            f.write(f"Session: {self.session_timestamp}\n")
            f.write(f"Model: {model_used}\n")
            f.write("=" * 60 + "\n")
            f.write("FINAL CODE RESPONSE:\n")
            f.write("=" * 60 + "\n")
            f.write(final_response)
            f.write("\n" + "=" * 60 + "\n")
        
        print(f"✅ Final response logged: {final_log_path}")
EOF

# STEP 2: Modify the orchestrate_full_pipeline function to include the mega prompt step
sed -i '/# Step 2: WIRE #3 FIX - Generate mixed content response for parser/i\
            # Step 2: ASSEMBLE MEGA PROMPT AND GENERATE FINAL CODE\
            mega_prompt = self._assemble_mega_prompt(user_request, bird_results["stage_results"])\
            final_code_result = self._generate_final_code_with_mega_prompt(mega_prompt)\
            \
            if not final_code_result["success"]:\
                print(f"⚠️ Final code generation failed: {final_code_result.get(\"error\")}")\
                # Continue with mixed content as fallback\
            else:\
                print(f"✅ FINAL CODE GENERATED: {final_code_result[\"characters\"]} characters")\
            \
            # Store final code result for later use\
            bird_results["final_code_result"] = final_code_result\
            \
            # Step 3: WIRE #3 FIX - Generate mixed content response for parser (keeping as fallback)\
' /home/flintx/peacock/core/out_homing.py

# STEP 3: Update the step numbers in comments
sed -i 's/# Step 2: WIRE #3 FIX - Generate mixed content response for parser/# Step 4: WIRE #3 FIX - Generate mixed content response for parser (fallback)/g' /home/flintx/peacock/core/out_homing.py

sed -i 's/# Step 3: Generate XEdit HTML interface/# Step 5: Generate XEdit HTML interface/g' /home/flintx/peacock/core/out_homing.py

# STEP 4: Create a sample .env file if it doesn't exist
if [ ! -f "/home/flintx/peacock/.env" ]; then
    echo "Creating sample .env file..."
    cat > /home/flintx/peacock/.env << 'EOF'
# Groq API Keys
GROQ_API_KEY=your_primary_api_key_here
GROQ_API_KEY_1=your_backup_api_key_1_here
GROQ_API_KEY_2=your_backup_api_key_2_here
GROQ_API_KEY_3=your_backup_api_key_3_here
GROQ_API_KEY_4=your_backup_api_key_4_here

# Model Configuration
FINAL_MODEL=meta-llama/llama-4-maverick-17b-128e-instruct
SPARK_MODEL=meta-llama/llama-4-scout-17b-16e-instruct
FALCON_MODEL=meta-llama/llama-4-maverick-17b-128e-instruct
EAGLE_MODEL=meta-llama/llama-4-scout-17b-16e-instruct
HAWK_MODEL=meta-llama/llama-4-maverick-17b-128e-instruct
EOF
fi

# STEP 5: Add dotenv import to the top of out_homing.py if not already there
if ! grep -q "from dotenv import load_dotenv" /home/flintx/peacock/core/out_homing.py; then
    sed -i '1s/^/import os\nfrom dotenv import load_dotenv\nload_dotenv()\n\n/' /home/flintx/peacock/core/out_homing.py
fi

# STEP 6: Remove any hardcoded API keys from out_homing.py
sed -i '/GROQ_API_KEYS = \[/,/\]/d' /home/flintx/peacock/core/out_homing.py

# STEP 7: Add environment-based API key loading
sed -i '/class OutHomingOrchestrator/a\
    # Load API keys from environment\
    GROQ_API_KEYS = [\
        os.getenv("GROQ_API_KEY"),\
        os.getenv("GROQ_API_KEY_1"),\
        os.getenv("GROQ_API_KEY_2"),\
        os.getenv("GROQ_API_KEY_3"),\
        os.getenv("GROQ_API_KEY_4")\
    ]\
    # Filter out None values\
    GROQ_API_KEYS = [key for key in GROQ_API_KEYS if key]' /home/flintx/peacock/core/out_homing.py

echo ""
echo "🎉 MEGA PROMPT ASSEMBLY AND FINAL CODE GENERATION ADDED!"
echo ""
echo "✅ WHAT WAS ADDED:"
echo "   🧠 _assemble_mega_prompt() - Combines all 4 bird outputs into mega prompt"
echo "   🎯 _generate_final_code_with_mega_prompt() - Sends mega prompt to Groq for code"
echo "   📋 _log_mega_prompt() - Creates megapromptlog-{session}.txt"
echo "   💾 _log_final_response() - Creates finalresponselog-{session}.txt"
echo "   🔄 Modified orchestrate_full_pipeline() to include the new step"
echo "   🔑 Properly uses API keys from .env file instead of hardcoding"
echo ""
echo "🔥 NOW YOUR WORKFLOW WILL BE:"
echo "   1. 🐦 Run 4 birds (Spark, Falcon, Eagle, Hawk)"
echo "   2. 🧠 Assemble mega prompt from all 4 outputs"  
echo "   3. 🎯 Send mega prompt to Groq for FINAL CODE GENERATION"
echo "   4. 📋 Log both mega prompt and final response"
echo "   5. 🎨 Generate XEdit interface with the final code"
echo ""
echo "🚀 TEST IT:"
echo "   python3 pea-mcp-1.py --log"
echo "   # Then trigger a prompt and check for the new log files!"