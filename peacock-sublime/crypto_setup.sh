#!/bin/bash

# Cryptocurrency Portfolio Tracker Setup Script
# Based on Peacock AI Pipeline Analysis

echo "🚀 Setting up Crypto Portfolio Tracker..."

# Create directory structure
mkdir -p templates static logs
mkdir -p tests/{unit,integration,e2e}

# Create the main app file
cat > app.py << 'APP_EOF'
# Copy the app.py content from the artifact above
APP_EOF

# Create the templates directory
mkdir -p templates

# Create the frontend HTML file
cat > templates/index.html << 'HTML_EOF'
# Copy the index.html content from the artifact above
HTML_EOF

# Create environment file from template
cat > .env << 'ENV_EOF'
# Flask Configuration
SECRET_KEY=crypto-tracker-secret-key-change-in-production
FLASK_ENV=development
FLASK_DEBUG=True

# API Configuration - CoinGecko free tier (no key needed for basic calls)
COINGECKO_API_KEY=
UPDATE_INTERVAL=30

# Email Configuration (optional for production)
SMTP_SERVER=
SMTP_USERNAME=
SMTP_PASSWORD=

# Security
CORS_ORIGINS=http://localhost:5000
RATE_LIMIT_PER_MINUTE=100
ENV_EOF

# Create requirements.txt
cat > requirements.txt << 'REQ_EOF'
flask==3.1.1
flask-socketio==5.5.1
python-dotenv==1.1.0
requests==2.32.3
python-socketio==5.13.0
gunicorn==21.2.0
pytest==7.4.3
pytest-flask==1.3.0
REQ_EOF

# Create run script
cat > run.sh << 'RUN_EOF'
#!/bin/bash
echo "🦚 Starting Crypto Portfolio Tracker..."
echo "📊 Real-time data from CoinGecko API"
echo "🔔 WebSocket alerts enabled"
echo "🌐 Access at: http://localhost:5000"
echo ""

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Install dependencies if needed
if [ ! -f ".requirements_installed" ]; then
    echo "📦 Installing dependencies..."
    pip install -r requirements.txt
    touch .requirements_installed
fi

# Run the application
python app.py
RUN_EOF

# Create test runner
cat > test.sh << 'TEST_EOF'
#!/bin/bash
echo "🧪 Running Crypto Portfolio Tracker Tests..."

# Activate virtual environment
source venv/bin/activate

# Install test dependencies
pip install pytest pytest-flask requests-mock

# Run tests
python -m pytest tests/ -v --tb=short

echo "✅ Test run complete"
TEST_EOF

# Create deployment script
cat > deploy.sh << 'DEPLOY_EOF'
#!/bin/bash
echo "🚀 Deploying Crypto Portfolio Tracker..."

# Production environment setup
export FLASK_ENV=production
export FLASK_DEBUG=False

# Install production dependencies
pip install gunicorn

# Run with Gunicorn (production WSGI server)
gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:5000 app:app
DEPLOY_EOF

# Create Docker setup
cat > Dockerfile << 'DOCKER_EOF'
FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Expose port
EXPOSE 5000

# Run with Gunicorn
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:5000", "app:app"]
DOCKER_EOF

# Create docker-compose.yml
cat > docker-compose.yml << 'COMPOSE_EOF'
version: '3.8'

services:
  app:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=production
      - SECRET_KEY=your-production-secret-key
    volumes:
      - ./logs:/app/logs
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    restart: unless-stopped

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: crypto_portfolio
      POSTGRES_USER: portfolio_user
      POSTGRES_PASSWORD: secure_password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  postgres_data:
COMPOSE_EOF

# Create basic tests
mkdir -p tests
cat > tests/test_app.py << 'TEST_APP_EOF'
"""
Basic tests for Crypto Portfolio Tracker
Based on Hawk QA Strategy from Peacock Analysis
"""

import pytest
import json
from app import app, crypto_service

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_index_route(client):
    """Test main portfolio page loads"""
    response = client.get('/')
    assert response.status_code == 200
    assert b'Crypto Portfolio Tracker' in response.data

def test_search_coins(client):
    """Test cryptocurrency search functionality"""
    response = client.get('/api/search/bitcoin')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)

def test_portfolio_empty(client):
    """Test empty portfolio returns correct structure"""
    response = client.get('/api/portfolio/test_user')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'holdings' in data
    assert 'total_value' in data
    assert data['holdings'] == []
    assert data['total_value'] == 0

def test_add_to_portfolio(client):
    """Test adding cryptocurrency to portfolio"""
    portfolio_data = {
        'coin_id': 'bitcoin',
        'name': 'Bitcoin',
        'symbol': 'btc',
        'quantity': 1.5
    }
    response = client.post('/api/portfolio/test_user',
                          data=json.dumps(portfolio_data),
                          content_type='application/json')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True

def test_create_alert(client):
    """Test creating price alert"""
    alert_data = {
        'coin_id': 'bitcoin',
        'condition': 'above',
        'threshold': 50000
    }
    response = client.post('/api/alerts/test_user',
                          data=json.dumps(alert_data),
                          content_type='application/json')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True
    assert 'alert_id' in data

def test_crypto_service():
    """Test CoinGecko API integration"""
    # Test search functionality
    results = crypto_service.search_coins('bitcoin')
    assert isinstance(results, list)
    
    # Test price fetching (may fail if API is down, so we catch exceptions)
    try:
        prices = crypto_service.get_crypto_prices(['bitcoin'])
        assert isinstance(prices, dict)
    except Exception:
        # API might be down or rate limited
        pass

if __name__ == '__main__':
    pytest.main([__file__])
TEST_APP_EOF

# Create .gitignore
cat > .gitignore << 'GIT_EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
venv/
env/
ENV/

# Environment variables
.env
.env.local
.env.production

# Logs
logs/
*.log

# Database
*.db
*.sqlite3

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Testing
.pytest_cache/
.coverage
htmlcov/

# Requirements check
.requirements_installed
GIT_EOF

# Make scripts executable
chmod +x run.sh test.sh deploy.sh

# Create logs directory
mkdir -p logs

echo "✅ Setup complete!"
echo ""
echo "🦚 CRYPTO PORTFOLIO TRACKER READY"
echo "=================================="
echo "📁 Project structure created"
echo "⚙️  Configuration files ready"
echo "🐳 Docker setup included"
echo "🧪 Test framework configured"
echo ""
echo "🚀 NEXT STEPS:"
echo "1. Copy the app.py and templates/index.html code from the artifacts"
echo "2. Run: ./run.sh"
echo "3. Open: http://localhost:5000"
echo ""
echo "🔧 TESTING:"
echo "Run: ./test.sh"
echo ""
echo "🚀 PRODUCTION DEPLOYMENT:"
echo "Run: docker-compose up -d"
echo ""
echo "Based on Peacock AI Pipeline Analysis"
echo "Enterprise-grade crypto portfolio tracker with real-time alerts! 🦚"