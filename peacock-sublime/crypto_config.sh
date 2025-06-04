# Cryptocurrency Portfolio Tracker Configuration
# Copy this to .env and add your actual values

# Flask Configuration
SECRET_KEY=your-super-secret-key-change-this-in-production
FLASK_ENV=development
FLASK_DEBUG=True

# API Configuration
COINGECKO_API_KEY=your-coingecko-api-key-here
# Note: CoinGecko's free tier doesn't require API key for basic calls
# But having one increases rate limits significantly

# Real-time Configuration
UPDATE_INTERVAL=30
MAX_CONNECTIONS=1000

# Alert Configuration
ENABLE_EMAIL_ALERTS=True
ENABLE_PUSH_NOTIFICATIONS=True

# Email Configuration (for production alerts)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# Twilio Configuration (for SMS alerts)
TWILIO_ACCOUNT_SID=your-twilio-account-sid
TWILIO_AUTH_TOKEN=your-twilio-auth-token
TWILIO_PHONE_NUMBER=+1234567890

# Database Configuration (for production)
DATABASE_URL=sqlite:///portfolio.db
# For PostgreSQL: postgresql://user:password@localhost/crypto_portfolio

# Redis Configuration (for production caching)
REDIS_URL=redis://localhost:6379/0

# Security Configuration
CORS_ORIGINS=http://localhost:3000,http://localhost:5000
RATE_LIMIT_PER_MINUTE=100

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=logs/app.log