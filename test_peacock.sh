#!/bin/bash
# Peacock Automated Testing & Logging Script

TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
TEST_LOG="/home/flintx/peacock/logs/test_results_${TIMESTAMP}.log"
METRICS_LOG="/home/flintx/peacock/logs/metrics.json"

echo "🧪 PEACOCK TESTING SESSION: $TIMESTAMP" | tee $TEST_LOG

# Test 1: Snake Game
echo "🐍 Testing Snake Game..." | tee -a $TEST_LOG
START_TIME=$(date +%s)

SNAKE_RESPONSE=$(curl -s -X POST http://127.0.0.1:8000/process \
  -H "Content-Type: application/json" \
  -d '{
    "command": "peacock_full",
    "text": "Build a snake game using Python and pygame. Should have snake movement, food collection, score tracking, and collision detection.",
    "language": "python",
    "original_request": "Snake Game"
  }')

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Log results
echo "Snake Game Results:" >> $TEST_LOG
echo "Duration: ${DURATION}s" >> $TEST_LOG
echo "Response: $SNAKE_RESPONSE" >> $TEST_LOG
echo "---" >> $TEST_LOG

# Test 2: Physics Game
echo "🎮 Testing Physics Bouncing Game..." | tee -a $TEST_LOG
START_TIME=$(date +%s)

PHYSICS_RESPONSE=$(curl -s -X POST http://127.0.0.1:8000/process \
  -H "Content-Type: application/json" \
  -d '{
    "command": "peacock_full",
    "text": "Build a physics simulation game with colorful geometric shapes that bounce around the screen. Include gravity, collision detection, mathematical particle movement, and mesmerizing visual effects.",
    "language": "python", 
    "original_request": "Bouncing Shapes Physics Game"
  }')

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Log results
echo "Physics Game Results:" >> $TEST_LOG
echo "Duration: ${DURATION}s" >> $TEST_LOG
echo "Response: $PHYSICS_RESPONSE" >> $TEST_LOG

# Extract metrics
SNAKE_SUCCESS=$(echo $SNAKE_RESPONSE | jq -r '.status // "error"')
PHYSICS_SUCCESS=$(echo $PHYSICS_RESPONSE | jq -r '.status // "error"')

# Update metrics log
cat >> $METRICS_LOG << EOL
{
  "timestamp": "$TIMESTAMP",
  "tests": [
    {
      "name": "snake_game",
      "status": "$SNAKE_SUCCESS",
      "duration": $DURATION
    },
    {
      "name": "physics_game", 
      "status": "$PHYSICS_SUCCESS",
      "duration": $DURATION
    }
  ]
}
EOL

echo "✅ Testing complete! Results logged to: $TEST_LOG"
echo "📊 Metrics updated: $METRICS_LOG"
