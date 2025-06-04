#!/usr/bin/env python3
"""
Cryptocurrency Portfolio Tracker with Real-Time Alerts
Main Flask application with WebSocket support
Based on Peacock AI Pipeline Analysis
"""

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import requests
import os
import time
import threading
from datetime import datetime
from dotenv import load_dotenv
import json

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global variables for real-time data
price_cache = {}
user_portfolios = {}
active_alerts = {}

# CoinGecko API configuration
COINGECKO_API_URL = "https://api.coingecko.com/api/v3"
UPDATE_INTERVAL = 30  # seconds

class CryptoDataService:
    """Service for fetching and caching cryptocurrency data"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CryptoPortfolioTracker/1.0'
        })
    
    def get_crypto_prices(self, coin_ids):
        """Fetch current prices for given cryptocurrencies"""
        try:
            if not coin_ids:
                return {}
            
            ids_param = ','.join(coin_ids)
            url = f"{COINGECKO_API_URL}/simple/price"
            params = {
                'ids': ids_param,
                'vs_currencies': 'usd',
                'include_24hr_change': 'true',
                'include_market_cap': 'true'
            }
            
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching crypto prices: {e}")
            return {}
    
    def search_coins(self, query):
        """Search for cryptocurrencies by name or symbol"""
        try:
            url = f"{COINGECKO_API_URL}/search"
            params = {'query': query}
            
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            return data.get('coins', [])[:10]  # Return top 10 results
            
        except requests.exceptions.RequestException as e:
            print(f"Error searching coins: {e}")
            return []

# Initialize services
crypto_service = CryptoDataService()

@app.route('/')
def index():
    """Main portfolio page"""
    return render_template('index.html')

@app.route('/api/search/<query>')
def search_coins(query):
    """Search for cryptocurrencies"""
    results = crypto_service.search_coins(query)
    return jsonify(results)

@app.route('/api/portfolio/<user_id>')
def get_portfolio(user_id):
    """Get user's portfolio"""
    portfolio = user_portfolios.get(user_id, [])
    
    # Calculate portfolio value
    total_value = 0
    for holding in portfolio:
        coin_id = holding['coin_id']
        quantity = holding['quantity']
        if coin_id in price_cache:
            current_price = price_cache[coin_id]['usd']
            holding['current_price'] = current_price
            holding['value'] = quantity * current_price
            total_value += holding['value']
        else:
            holding['current_price'] = 0
            holding['value'] = 0
    
    return jsonify({
        'holdings': portfolio,
        'total_value': total_value
    })

@app.route('/api/portfolio/<user_id>', methods=['POST'])
def add_to_portfolio(user_id):
    """Add cryptocurrency to user's portfolio"""
    data = request.get_json()
    
    if user_id not in user_portfolios:
        user_portfolios[user_id] = []
    
    # Check if coin already exists in portfolio
    existing_holding = None
    for holding in user_portfolios[user_id]:
        if holding['coin_id'] == data['coin_id']:
            existing_holding = holding
            break
    
    if existing_holding:
        # Update existing holding
        existing_holding['quantity'] += data['quantity']
    else:
        # Add new holding
        user_portfolios[user_id].append({
            'coin_id': data['coin_id'],
            'name': data['name'],
            'symbol': data['symbol'],
            'quantity': data['quantity'],
            'added_at': datetime.now().isoformat()
        })
    
    return jsonify({'success': True})

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
