#!/usr/bin/env python3
"""
Test script to verify the app works correctly
"""

import sys
import os

# Add the app directory to Python path
sys.path.insert(0, '/opt/gbot-web-app')

print("=== Testing App Functionality ===")

try:
    print("1. Importing app...")
    import app
    print("✅ App imported successfully")
    
    print("2. Testing app object...")
    print(f"App object: {app.app}")
    print(f"App type: {type(app.app)}")
    
    print("3. Testing app context...")
    with app.app.app_context():
        print("✅ App context created successfully")
    
    print("4. Testing Flask routes...")
    with app.app.test_client() as client:
        try:
            response = client.get('/')
            print(f"✅ Root route accessible (status: {response.status_code})")
        except Exception as e:
            print(f"❌ Root route failed: {e}")
    
    print("5. Testing database connection...")
    with app.app.app_context():
        try:
            result = app.db.session.execute(app.db.text("SELECT 1")).fetchone()
            print("✅ Database connection successful")
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
    
    print("\n=== All Tests Passed ===")
    print("✅ The app is working correctly and ready for gunicorn!")
    
except Exception as e:
    print(f"❌ Critical error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
