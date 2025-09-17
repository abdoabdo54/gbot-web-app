#!/bin/bash

# Test script to verify gunicorn configuration

echo "🧪 Testing Gunicorn Configuration..."

# Check if gunicorn is installed
if ! command -v gunicorn &> /dev/null; then
    echo "❌ Gunicorn not found in PATH"
    exit 1
fi

# Check if config file exists
if [ ! -f "/opt/gbot-web-app/gunicorn.conf.py" ]; then
    echo "❌ Gunicorn config file not found"
    exit 1
fi

# Test gunicorn config syntax
echo "🔍 Testing config file syntax..."
cd /opt/gbot-web-app
python3 -c "import gunicorn.conf; print('✅ Config syntax OK')" 2>/dev/null || {
    echo "❌ Config syntax error"
    exit 1
}

# Test if app can be imported
echo "🔍 Testing app import..."
python3 -c "import app; print('✅ App import OK')" 2>/dev/null || {
    echo "❌ App import error"
    exit 1
}

echo "✅ All tests passed! Gunicorn should work."
