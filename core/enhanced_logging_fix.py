# Enhanced logging functions for pea-mcp.py

def log_prompt_raw(stage, prompt_text, model):
    """Log complete raw prompt"""
    if not LOGGING_ENABLED:
        return
    
    log_file = f"/home/flintx/peacock/logs/promptlog-{SESSION_TIMESTAMP}.txt"
    timestamp = datetime.datetime.now().strftime('%H:%M:%S')
    
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(f"\n{'='*80}\n")
        f.write(f"[{timestamp}] STAGE: {stage} | MODEL: {model}\n")
        f.write(f"{'='*80}\n")
        f.write(f"PROMPT:\n{prompt_text}\n")
        f.write(f"{'='*80}\n\n")

def log_response_raw(stage, response_text, char_count):
    """Log complete raw response"""
    if not LOGGING_ENABLED:
        return
    
    log_file = f"/home/flintx/peacock/logs/responselog-{SESSION_TIMESTAMP}.txt"
    timestamp = datetime.datetime.now().strftime('%H:%M:%S')
    
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(f"\n{'='*80}\n")
        f.write(f"[{timestamp}] STAGE: {stage} | CHARS: {char_count}\n")
        f.write(f"{'='*80}\n")
        f.write(f"RESPONSE:\n{response_text}\n")
        f.write(f"{'='*80}\n\n")

def log_groq_api_call(model, prompt, response):
    """Log complete GROQ API interaction"""
    if not LOGGING_ENABLED:
        return
    
    log_file = f"/home/flintx/peacock/logs/promptlog-{SESSION_TIMESTAMP}.txt"
    timestamp = datetime.datetime.now().strftime('%H:%M:%S')
    
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(f"\n🤖 GROQ API CALL [{timestamp}]\n")
        f.write(f"Model: {model}\n")
        f.write(f"Prompt Length: {len(prompt)} chars\n")
        f.write(f"{'─'*60}\n")
        f.write(f"PROMPT:\n{prompt}\n")
        f.write(f"{'─'*60}\n")
        
    response_file = f"/home/flintx/peacock/logs/responselog-{SESSION_TIMESTAMP}.txt"
    with open(response_file, 'a', encoding='utf-8') as f:
        f.write(f"\n🤖 GROQ RESPONSE [{timestamp}]\n")
        f.write(f"Model: {model}\n")
        f.write(f"Response Length: {len(response)} chars\n")
        f.write(f"{'─'*60}\n")
        f.write(f"RESPONSE:\n{response}\n")
        f.write(f"{'─'*60}\n")
