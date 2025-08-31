#!/usr/bin/env python3
"""
Development server runner for GBot Web App
Sets up environment for testing SMTP functionality
"""

import os
import sys

# Set development environment variables
os.environ['SECRET_KEY'] = 'dev-secret-key-for-testing-123456789'
os.environ['WHITELIST_TOKEN'] = 'dev-whitelist-token-123456789'
os.environ['DATABASE_URL'] = 'sqlite:///instance/test.db'
os.environ['DEBUG'] = 'True'
os.environ['FLASK_ENV'] = 'development'
os.environ['LOG_LEVEL'] = 'DEBUG'
os.environ['ENABLE_IP_WHITELIST'] = 'False'
os.environ['ALLOW_ALL_IPS_IN_DEV'] = 'True'
os.environ['SESSION_COOKIE_SECURE'] = 'False'

print("=== GBot Development Server ===")
print("Environment configured for local development")
print("Database: SQLite (instance/test.db)")
print("IP Whitelist: Disabled")
print("Debug Mode: Enabled")
print("=====================================")

try:
    # Import and run the app
    from app import app
    
    print("\n=== Available API Routes ===")
    api_routes = []
    for rule in app.url_map.iter_rules():
        if '/api/' in rule.rule:
            api_routes.append(f"  {rule.rule} {list(rule.methods)}")
    
    api_routes.sort()
    for route in api_routes[:10]:  # Show first 10 API routes
        print(route)
    
    smtp_exists = any('/api/test-smtp' in route for route in api_routes)
    print(f"  ... and {len(api_routes) - 10} more routes")
    print(f"\nSMTP Route Available: {'✅ YES' if smtp_exists else '❌ NO'}")
    print("=====================================")
    
    print("\n🚀 Starting Flask Development Server...")
    print("SMTP endpoint available at: http://localhost:5000/api/test-smtp")
    print("Dashboard available at: http://localhost:5000/dashboard")
    print("Press Ctrl+C to stop\n")
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)
    
except Exception as e:
    print(f"❌ Error starting server: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
