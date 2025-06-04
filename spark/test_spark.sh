#!/bin/bash

USER_REQUEST="$1"
if [ -z "$USER_REQUEST" ]; then
    echo "Usage: ./test_spark.sh 'your project description'"
    exit 1
fi

echo "=== Testing Spark 4-Stage Analysis ==="
echo "Project: $USER_REQUEST"
echo

# Test Stage 1
echo "Stage 1: Task Analysis"
RESPONSE=$(curl -s -X POST "https://api.groq.com/openai/v1/chat/completions" \
  -H "Authorization: Bearer $GROQ_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"messages\": [{\"role\": \"user\", \"content\": \"$(cat stage1_prompt.txt | sed "s/{USER_INPUT}/$USER_REQUEST/g")\"}],
    \"model\": \"qwen-qwq-32b\"
  }")

# Extract just the JSON content from the model's response
STAGE1_CONTENT=$(echo "$RESPONSE" | jq -r '.choices[0].message.content')

# Extract the JSON part (everything between first { and last })
STAGE1_JSON=$(echo "$STAGE1_CONTENT" | sed -n '/^{/,/^}$/p' | tail -n +1)

echo "$STAGE1_JSON" | jq .
echo

# Save for next stages
echo "$STAGE1_JSON" > stage1_output.json
