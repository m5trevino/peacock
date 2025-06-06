#!/bin/bash

PROJECT="$1"
if [ -z "$PROJECT" ]; then
    echo "Usage: ./peacock.sh 'your project description'"
    echo "Example: ./peacock.sh 'Create a todo list app with file storage'"
    exit 1
fi

echo "🦚 PEACOCK AI PIPELINE INITIATED 🦚"
echo "Project: $PROJECT"
echo "========================================"

./simple_test.sh "$PROJECT"
echo
./falcon_test.sh "$PROJECT"  
echo
./eagle_test.sh "$PROJECT"
echo
./hawk_test.sh "$PROJECT"

echo
echo "🦚 PEACOCK ANALYSIS COMPLETE 🦚"
echo "Your project is ready for implementation!"
