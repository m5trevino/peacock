#!/bin/bash

USER_REQUEST="$1"
if [ -z "$USER_REQUEST" ]; then
    echo "Usage: ./eagle_test.sh 'project description'"
    exit 1
fi

echo "=== Peacock Stage 3: Eagle Implementation ==="
echo "Project: $USER_REQUEST"
echo

# Eagle focuses on immediate, actionable implementation steps
curl -s -X POST "https://api.groq.com/openai/v1/chat/completions" \
  -H "Authorization: Bearer $GROQ_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"messages\": [{
      \"role\": \"user\", 
      \"content\": \"You are Eagle, implementation specialist. Project: $USER_REQUEST. Provide immediate implementation steps: 1) Setup commands 2) Directory structure creation 3) Key files to create first 4) Initial code scaffolding 5) First working prototype steps. Be specific and executable.\"
    }],
    \"model\": \"qwen-qwq-32b\"
  }" | jq -r '.choices[0].message.content'

echo
echo "=== Next: Run Hawk (Stage 4) ==="
