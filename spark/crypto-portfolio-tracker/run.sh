#!/bin/bash
echo "🦚 Starting Crypto Portfolio Tracker..."
echo "📊 Real-time data from CoinGecko API"
echo "🌐 Access at: http://localhost:5000"
echo ""

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Run the application
python app.py
