#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

echo "[Entrypoint] Starting container setup..."

# Source .env file if it exists to load variables
if [ -f /app/.env ]; then
  echo "[Entrypoint] Loading environment variables from /app/.env"
  set -a # Automatically export all variables sourced
  source /app/.env
  set +a # Stop automatically exporting
fi

# --- Pre-flight Checks & Setup ---
echo "[Entrypoint] Configuring Ngrok Auth Token..."
if [ -z "$NGROK_AUTHTOKEN" ]; then
  echo "[Entrypoint] Error: NGROK_AUTHTOKEN not set in .env file! Ngrok will likely fail."
  # exit 1 # Exit if token is critical
else
  # Use --log=stderr to avoid cluttering stdout unless debugging
  ngrok config add-authtoken $NGROK_AUTHTOKEN --log=stderr
  echo "[Entrypoint] Ngrok token configured."
fi

if [ -z "$NGROK_DOMAIN" ]; then
  echo "[Entrypoint] Error: NGROK_DOMAIN not set in .env file! Vite/Ngrok setup will fail."
  exit 1 # Exit because validate_setup.py needs it
fi
echo "[Entrypoint] Using Ngrok domain: $NGROK_DOMAIN"

echo "[Entrypoint] Running LLM setup via huggingface.py..."
# Pass token via env var HUGGING_FACE_HUB_TOKEN if needed
python3 /app/huggingface.py
echo "[Entrypoint] huggingface.py finished."

echo "[Entrypoint] Running Bolt.DIY validation/setup via validate_setup.py..."
# This script MUST now correctly read NGROK_DOMAIN and patch vite.config.ts
# Ensure validate_setup.py exists and is executable
if [ -f "/app/scripts/validate_setup.py" ]; then
    python3 /app/scripts/validate_setup.py
    echo "[Entrypoint] validate_setup.py finished."
else
    echo "[Entrypoint] Warning: /app/scripts/validate_setup.py not found. Skipping Bolt.DIY validation."
fi

echo "[Entrypoint] Setting git safe directory for bolt.diy..."
# Needed because mount owner (host user) != container user (root)
# Use --system if possible, --global affects root user's config in container
git config --global --add safe.directory /app/bolt.diy || echo "[Entrypoint] Git safe directory already set or git not configured."
echo "[Entrypoint] Git safe directory set."

echo "[Entrypoint] Setup complete. Handing over to Supervisor..."
# Execute supervisord using the configuration file from /app
exec /usr/bin/supervisord -n -c /app/supervisord.conf
