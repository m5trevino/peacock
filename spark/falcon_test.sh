#!/bin/bash

USER_REQUEST="$1"
if [ -z "$USER_REQUEST" ]; then
    echo "Usage: ./falcon_test.sh 'project description'"
    exit 1
fi

echo "=== Peacock Stage 2: Falcon Architecture ==="
echo "Project: $USER_REQUEST"
echo

# Feed Spark's analysis to Falcon
curl -s -X POST "https://api.groq.com/openai/v1/chat/completions" \
  -H "Authorization: Bearer $GROQ_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"messages\": [{
      \"role\": \"user\", 
      \"content\": \"You are Falcon, solution architect. Project: $USER_REQUEST. Design the technical approach: 1) Technology stack 2) Architecture pattern 3) File structure 4) Data flow 5) Key implementation decisions. Be specific and practical.\"
    }],
    \"model\": \"qwen-qwq-32b\"
  }" | jq -r '.choices[0].message.content'

echo
echo "=== Next: Run Eagle (Stage 3) ==="
