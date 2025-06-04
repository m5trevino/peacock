#!/bin/bash

USER_REQUEST="$1"
if [ -z "$USER_REQUEST" ]; then
    echo "Usage: ./simple_test.sh 'your project description'"
    exit 1
fi

echo "=== Peacock Stage 1: Spark Analysis ==="
echo "Project: $USER_REQUEST"
echo

# Call Spark with cleaner prompt
curl -s -X POST "https://api.groq.com/openai/v1/chat/completions" \
  -H "Authorization: Bearer $GROQ_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"messages\": [{
      \"role\": \"user\", 
      \"content\": \"You are Spark, requirements analyst. Project: $USER_REQUEST. Give me: 1) Core objective 2) Current state 3) Target state 4) What's in scope 5) What's out of scope. Be concise and strategic.\"
    }],
    \"model\": \"qwen-qwq-32b\"
  }" | jq -r '.choices[0].message.content'

echo
echo "=== Next: Run Falcon (Stage 2) ==="
