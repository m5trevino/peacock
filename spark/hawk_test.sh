#!/bin/bash

USER_REQUEST="$1"
if [ -z "$USER_REQUEST" ]; then
    echo "Usage: ./hawk_test.sh 'project description'"
    exit 1
fi

echo "=== Peacock Stage 4: Hawk Quality Assurance ==="
echo "Project: $USER_REQUEST"
echo

# Hawk focuses on testing, validation, and quality checks
curl -s -X POST "https://api.groq.com/openai/v1/chat/completions" \
  -H "Authorization: Bearer $GROQ_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"messages\": [{
      \"role\": \"user\", 
      \"content\": \"You are Hawk, quality assurance specialist. Project: $USER_REQUEST. Provide comprehensive QA strategy: 1) Test cases to verify 2) Security validation 3) Performance considerations 4) Error handling scenarios 5) Production readiness checklist. Be thorough and practical.\"
    }],
    \"model\": \"qwen-qwq-32b\"
  }" | jq -r '.choices[0].message.content'

echo
echo "=== Peacock Analysis Complete ==="
