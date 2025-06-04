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

def background_price_updater():
    """Background thread to update cryptocurrency prices"""
    global price_cache
    
    while True:
        try:
            # Get all unique coin IDs from all portfolios
            all_coin_ids = set()
            for portfolio in user_portfolios.values():
                for holding in portfolio:
                    all_coin_ids.add(holding['coin_id'])
            
            if all_coin_ids:
                # Fetch latest prices
                new_prices = crypto_service.get_crypto_prices(list(all_coin_ids))
                
                if new_prices:
                    price_cache.update(new_prices)
                    
                    # Check alerts and emit price updates
                    check_alerts(new_prices)
                    
                    # Emit price updates to all connected clients
                    socketio.emit('price_update', {
                        'prices': new_prices,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    print(f"Updated prices for {len(new_prices)} coins")
            
        except Exception as e:
            print(f"Error in background price updater: {e}")
        
        time.sleep(UPDATE_INTERVAL)

def check_alerts(new_prices):
    """Check if any price alerts should be triggered"""
    for user_id, alerts in active_alerts.items():
        for alert_id, alert in alerts.items():
            coin_id = alert['coin_id']
            condition = alert['condition']  # 'above' or 'below'
            threshold = alert['threshold']
            
            if coin_id in new_prices:
                current_price = new_prices[coin_id]['usd']
                
                # Check if alert condition is met
                should_trigger = False
                if condition == 'above' and current_price >= threshold:
                    should_trigger = True
                elif condition == 'below' and current_price <= threshold:
                    should_trigger = True
                
                if should_trigger:
                    # Emit alert to specific user
                    socketio.emit('alert_triggered', {
                        'alert_id': alert_id,
                        'coin_id': coin_id,
                        'current_price': current_price,
                        'threshold': threshold,
                        'condition': condition,
                        'message': f"{coin_id.upper()} is {condition} ${threshold}"
                    }, room=user_id)
                    
                    # Remove one-time alert
                    if not alert.get('recurring', False):
                        del active_alerts[user_id][alert_id]

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

@app.route('/api/alerts/<user_id>')
def get_alerts(user_id):
    """Get user's alerts"""
    alerts = active_alerts.get(user_id, {})
    return jsonify(list(alerts.values()))

@app.route('/api/alerts/<user_id>', methods=['POST'])
def create_alert(user_id):
    """Create price alert for user"""
    data = request.get_json()
    
    if user_id not in active_alerts:
        active_alerts[user_id] = {}
    
    alert_id = f"alert_{len(active_alerts[user_id]) + 1}"
    active_alerts[user_id][alert_id] = {
        'id': alert_id,
        'coin_id': data['coin_id'],
        'condition': data['condition'],  # 'above' or 'below'
        'threshold': float(data['threshold']),
        'recurring': data.get('recurring', False),
        'created_at': datetime.now().isoformat()
    }
    
    return jsonify({'success': True, 'alert_id': alert_id})

@app.route('/api/alerts/<user_id>/<alert_id>', methods=['DELETE'])
def delete_alert(user_id, alert_id):
    """Delete user's alert"""
    if user_id in active_alerts and alert_id in active_alerts[user_id]:
        del active_alerts[user_id][alert_id]
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Alert not found'}), 404

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print(f"Client connected: {request.sid}")
    
    # Send current price cache to new client
    if price_cache:
        emit('price_update', {
            'prices': price_cache,
            'timestamp': datetime.now().isoformat()
        })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print(f"Client disconnected: {request.sid}")

@socketio.on('join_user_room')
def handle_join_room(data):
    """Join user to their personal room for alerts"""
    user_id = data['user_id']
    socketio.server.enter_room(request.sid, user_id)
    print(f"User {user_id} joined their room")

if __name__ == '__main__':
    # Start background price updater thread
    updater_thread = threading.Thread(target=background_price_updater, daemon=True)
    updater_thread.start()
    
    # Run the Flask-SocketIO server
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
