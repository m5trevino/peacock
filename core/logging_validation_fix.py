# Quick patch for your current peamcp.py

# Replace the validate_response_quality function with this fixed version:

def validate_response_quality(response_content, command):
    """Enhanced quality validation with better logic"""
    
    # Check for basic content
    if len(response_content.strip()) < 50:
        print(f"         └─ VALIDATION FAILED: Response too short ({len(response_content)} chars)")
        return False
    
    # Different validation for different command types
    analysis_commands = ["spark_analysis", "falcon_architecture", "hawk_qa"]
    implementation_commands = ["eagle_implementation", "code_analysis"]
    
    if command in analysis_commands:
        # Analysis commands should have structured content but JSON is optional
        print(f"         └─ VALIDATION: Analysis command, checking structure...")
        
        # Look for structured sections (## headers, ** bold **, bullet points)
        has_structure = any([
            "**" in response_content,  # Bold headers
            "##" in response_content,  # Markdown headers  
            "- " in response_content,  # Bullet points
            "1." in response_content   # Numbered lists
        ])
        
        if has_structure:
            print(f"         └─ VALIDATION PASSED: Found structured content")
            return True
        else:
            print(f"         └─ VALIDATION FAILED: No structured content found")
            return False
            
    elif command in implementation_commands:
        # Implementation commands should have code blocks
        print(f"         └─ VALIDATION: Implementation command, checking for code...")
        
        # Look for code indicators
        has_code = any([
            "```" in response_content,     # Code blocks
            "filename:" in response_content, # File definitions
            "class " in response_content,   # Class definitions
            "function " in response_content, # Function definitions
            "def " in response_content,     # Python functions
            "<html>" in response_content    # HTML content
        ])
        
        if has_code:
            print(f"         └─ VALIDATION PASSED: Found code content")
            return True
        else:
            print(f"         └─ VALIDATION FAILED: No code content found")
            return False
    
    # Default: just check it's substantial
    print(f"         └─ VALIDATION: General command, checking length...")
    return len(response_content.strip()) >= 100

# Enhanced logging function - replace call_optimized_groq with this:

def call_optimized_groq(prompt, command):
    """Call Groq with optimized model selection, enhanced logging and better validation"""
    
    primary_model = select_optimal_model(command)
    fallback_models = [
        PEACOCK_MODEL_STRATEGY["speed_model"], 
        PEACOCK_MODEL_STRATEGY["fallback_model"]
    ]
    
    # Build models to try (primary + fallbacks, avoid duplicates)
    models_to_try = [primary_model] + [m for m in fallback_models if m != primary_model]
    
    cli_progress(command.upper(), "START", f"Using {primary_model}")
    
    # ENHANCED LOGGING: Always log prompts if logging is enabled
    if LOGGING_ENABLED:
        prompt_log_file = f"/home/flintx/peacock/logs/promptlog-{SESSION_TIMESTAMP}.txt"
        with open(prompt_log_file, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {command.upper()} PROMPT TO {primary_model}\n")
            f.write("=" * 80 + "\n")
            f.write(f"STAGE: {command}\n")
            f.write(f"PROMPT LENGTH: {len(prompt)} chars\n")
            f.write("-" * 40 + "\n")
            f.write(prompt)
            f.write("\n" + "=" * 80 + "\n\n")
    
    for model in models_to_try:
        try:
            from groq import Groq
            client = Groq(api_key=GROQ_API_KEY)
            
            cli_progress(command.upper(), "WORKING", f"Calling {model}...")
            
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=GROQ_CONFIG["temperature"],
                max_tokens=GROQ_CONFIG["max_tokens"],
                top_p=GROQ_CONFIG["top_p"]
                # NO response_format parameter - this is critical
            )
            
            content = response.choices[0].message.content
            
            # ENHANCED LOGGING: Always log responses if logging is enabled
            if LOGGING_ENABLED:
                response_log_file = f"/home/flintx/peacock/logs/response-{SESSION_TIMESTAMP}.txt"
                with open(response_log_file, "a", encoding="utf-8") as f:
                    f.write(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {command.upper()} RESPONSE FROM {model}\n")
                    f.write("=" * 80 + "\n")
                    f.write(f"STAGE: {command}\n")
                    f.write(f"MODEL: {model}\n")
                    f.write(f"LENGTH: {len(content)} chars\n")
                    f.write("-" * 40 + "\n")
                    f.write(content)
                    f.write("\n" + "=" * 80 + "\n\n")
            
            # Validate response quality with enhanced logic
            if validate_response_quality(content, command):
                cli_progress(command.upper(), "SUCCESS", f"Model: {model}, Length: {len(content)} chars")
                
                return {
                    "success": True,
                    "text": content,
                    "model_used": model
                }
            else:
                print(f"         └─ Quality validation failed for {model}")
                continue
                
        except Exception as e:
            cli_progress(command.upper(), "ERROR", f"Model {model} failed", str(e))
            
            if LOGGING_ENABLED:
                error_log_file = f"/home/flintx/peacock/logs/mcplog-{SESSION_TIMESTAMP}.txt"
                with open(error_log_file, "a", encoding="utf-8") as f:
                    f.write(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {command.upper()} ERROR - {model}: {e}\n")
            continue
    
    return {
        "success": False, 
        "error": "All models failed quality validation",
        "models_tried": models_to_try
    }