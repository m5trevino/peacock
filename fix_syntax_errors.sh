#!/bin/bash
# Fix the syntax errors in the test files

cd /home/flintx/apitest/py

echo "🔧 FIXING SYNTAX ERRORS IN TEST FILES..."

# Fix the PROXY_CONFIG placement issue
for file in *.py; do
    if [[ -f "$file" && "$file" != "master_test_runner.py" && "$file" != "run_peacock_validators.py" && "$file" != "peacock_workflow_validator.py" && "$file" != "mega_prompt_quality_analyzer.py" ]]; then
        echo "   🔧 Fixing $file"
        
        # Remove the broken PROXY_CONFIG sections
        sed -i '/^PROXY_CONFIG = {$/,/^}$/d' "$file"
        sed -i '/^def make_groq_request_with_proxy/,/^    return None$/d' "$file"
        
        # Add the proxy configuration properly after imports
        if ! grep -q "PROXY_CONFIG" "$file"; then
            # Find where to insert (after imports, before main code)
            if grep -q "^import\|^from" "$file"; then
                # Insert after the last import
                sed -i '/^import\|^from/a\
\
# PROXY CONFIGURATION WITH FALLBACK\
PROXY_CONFIG = {\
    "http": "http://0aa180faa467ad67809b__cr.us:6dc612d4a08ca89d@gw.dataimpulse.com:823",\
    "https": "http://0aa180faa467ad67809b__cr.us:6dc612d4a08ca89d@gw.dataimpulse.com:823"\
}\
\
def make_groq_request_with_proxy(client, **kwargs):\
    """Make Groq request with proxy fallback"""\
    for attempt in range(3):\
        try:\
            return client.chat.completions.create(**kwargs)\
        except Exception as e:\
            print(f"⚠️ Request attempt {attempt + 1} failed: {e}")\
            if attempt == 2:\
                print("❌ All attempts failed")\
                raise\
    return None' "$file"
            fi
        fi
        
        # Restore the client.chat.completions.create calls (remove proxy wrapper for now)
        sed -i 's/make_groq_request_with_proxy(client, /client.chat.completions.create(/g' "$file"
    fi
done

echo "✅ Fixed syntax errors in test files!"
echo "🚀 Try running the tests again..."