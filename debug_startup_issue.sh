#!/bin/bash

echo "🔍 Debugging Application Startup Issue..."

echo ""
echo "📋 Checking Gunicorn error logs:"
if [ -f "gunicorn-error.log" ]; then
    echo "=== Last 50 lines of gunicorn-error.log ==="
    tail -50 gunicorn-error.log
else
    echo "❌ gunicorn-error.log not found"
fi

echo ""
echo "📋 Checking Gunicorn access logs:"
if [ -f "gunicorn-access.log" ]; then
    echo "=== Last 20 lines of gunicorn-access.log ==="
    tail -20 gunicorn-access.log
else
    echo "❌ gunicorn-access.log not found"
fi

echo ""
echo "📋 Checking application logs:"
if [ -f "app.log" ]; then
    echo "=== Last 30 lines of app.log ==="
    tail -30 app.log
else
    echo "❌ app.log not found"
fi

echo ""
echo "🔧 Testing application directly (without Gunicorn):"
echo "Activating virtual environment and testing app startup..."

# Activate virtual environment
source venv/bin/activate

# Set environment variables
export $(grep -v '^#' .env | xargs)

# Ensure we're using the PostgreSQL database URL
if [ -f ".db_credentials" ]; then
    source .db_credentials
    export DATABASE_URL
fi

echo "Testing Python imports..."
python3 -c "
import sys
print('Python version:', sys.version)

try:
    print('Testing Flask import...')
    import flask
    print('✅ Flask imported successfully')
except Exception as e:
    print('❌ Flask import failed:', e)

try:
    print('Testing app import...')
    from app import app
    print('✅ App imported successfully')
except Exception as e:
    print('❌ App import failed:', e)
    import traceback
    traceback.print_exc()

try:
    print('Testing database import...')
    from database import db
    print('✅ Database imported successfully')
except Exception as e:
    print('❌ Database import failed:', e)
    import traceback
    traceback.print_exc()

try:
    print('Testing config import...')
    from config import *
    print('✅ Config imported successfully')
except Exception as e:
    print('❌ Config import failed:', e)
    import traceback
    traceback.print_exc()
"

echo ""
echo "🔧 Testing app context..."
python3 -c "
try:
    from app import app, db
    with app.app_context():
        print('✅ App context created successfully')
        print('Testing database connection...')
        db.engine.execute('SELECT 1')
        print('✅ Database connection successful')
except Exception as e:
    print('❌ App context or database failed:', e)
    import traceback
    traceback.print_exc()
"

echo ""
echo "🔧 Testing Gunicorn directly..."
cd /opt/gbot-web-app
source venv/bin/activate
export $(grep -v '^#' .env | xargs)
if [ -f ".db_credentials" ]; then
    source .db_credentials
    export DATABASE_URL
fi

echo "Running Gunicorn in foreground to see errors..."
timeout 10s venv/bin/gunicorn --workers 1 --bind 127.0.0.1:8000 --timeout 30 app:app || echo "Gunicorn test completed (timeout or error)"

echo ""
echo "📋 Environment variables check:"
echo "DATABASE_URL: $DATABASE_URL"
echo "SECRET_KEY: ${SECRET_KEY:0:10}..."
echo "ENABLE_IP_WHITELIST: $ENABLE_IP_WHITELIST"
echo "ALLOW_ALL_IPS_IN_DEV: $ALLOW_ALL_IPS_IN_DEV"

echo ""
echo "📋 File permissions check:"
ls -la *.py
ls -la templates/
ls -la static/

echo ""
echo "🔧 Checking for missing dependencies..."
python3 -c "
import pkg_resources
required = ['flask', 'flask-sqlalchemy', 'werkzeug', 'gunicorn']
installed = [pkg.key for pkg in pkg_resources.working_set]
missing = [pkg for pkg in required if pkg not in installed]
if missing:
    print('❌ Missing packages:', missing)
else:
    print('✅ All required packages installed')
"
