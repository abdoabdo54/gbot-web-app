#!/usr/bin/env python3
"""
Test script for the upgraded GBot Web App with remote account management
"""

import sys
import os

def test_imports():
    """Test if all required modules can be imported"""
    print("Testing imports...")
    
    try:
        import paramiko
        print("✅ paramiko imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import paramiko: {e}")
        return False
    
    try:
        import undetected_chromedriver as uc
        print("✅ undetected_chromedriver imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import undetected_chromedriver: {e}")
        return False
    
    try:
        from selenium import webdriver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        print("✅ selenium imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import selenium: {e}")
        return False
    
    try:
        from remote_account_manager import account_manager
        print("✅ remote_account_manager imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import remote_account_manager: {e}")
        return False
    
    return True

def test_server_connection():
    """Test connection to the remote server"""
    print("\nTesting server connection...")
    
    try:
        from remote_account_manager import account_manager
        
        # Test server connection
        accounts = account_manager.retrieve_accounts_from_server()
        
        if accounts:
            print(f"✅ Successfully connected to server and retrieved {len(accounts)} accounts")
            print("Sample accounts:")
            for i, acc in enumerate(accounts[:3]):  # Show first 3 accounts
                print(f"  {i+1}. {acc['account']}")
            if len(accounts) > 3:
                print(f"  ... and {len(accounts) - 3} more")
            return True
        else:
            print("⚠️  Connected to server but no accounts found")
            return True
            
    except Exception as e:
        print(f"❌ Failed to connect to server: {e}")
        return False

def test_chrome_setup():
    """Test Chrome driver setup (without actually launching)"""
    print("\nTesting Chrome driver setup...")
    
    try:
        from remote_account_manager import account_manager
        
        # Test Chrome options setup
        options = account_manager.setup_chrome_driver(headless=True)
        
        if options:
            print("✅ Chrome driver setup successful")
            return True
        else:
            print("❌ Chrome driver setup failed")
            return False
            
    except Exception as e:
        print(f"❌ Chrome driver setup error: {e}")
        return False

def main():
    """Main test function"""
    print("=" * 50)
    print("GBot Web App - Remote Account Management Test")
    print("=" * 50)
    
    # Test imports
    if not test_imports():
        print("\n❌ Import tests failed. Please install missing dependencies.")
        sys.exit(1)
    
    # Test server connection
    if not test_server_connection():
        print("\n⚠️  Server connection failed. This may be expected if server is not available.")
    
    # Test Chrome setup
    if not test_chrome_setup():
        print("\n⚠️  Chrome setup failed. This may be expected if Chrome is not installed.")
    
    print("\n" + "=" * 50)
    print("Test completed!")
    print("=" * 50)
    print("\nTo start the application:")
    print("1. Install dependencies: pip install -r requirements.txt")
    print("2. Run the app: python app.py")
    print("3. Access the web interface at: http://localhost:5000")

if __name__ == "__main__":
    main()
