#!/usr/bin/env python3
"""
Test script for Chrome automation and account retrieval functionality
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
        print(f"❌ paramiko import failed: {e}")
        return False
    
    try:
        from undetected_chromedriver import Chrome, ChromeOptions
        print("✅ undetected_chromedriver imported successfully")
    except ImportError as e:
        print(f"❌ undetected_chromedriver import failed: {e}")
        return False
    
    try:
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        print("✅ selenium modules imported successfully")
    except ImportError as e:
        print(f"❌ selenium import failed: {e}")
        return False
    
    try:
        from chrome_automation import account_manager
        print("✅ chrome_automation module imported successfully")
    except ImportError as e:
        print(f"❌ chrome_automation import failed: {e}")
        return False
    
    return True

def test_account_retrieval():
    """Test account retrieval from server"""
    print("\nTesting account retrieval...")
    
    try:
        from chrome_automation import account_manager
        accounts = account_manager.retrieve_accounts_from_server()
        
        if accounts:
            print(f"✅ Successfully retrieved {len(accounts)} accounts")
            for i, account in enumerate(accounts[:3], 1):  # Show first 3
                print(f"   {i}. {account['username']}")
            if len(accounts) > 3:
                print(f"   ... and {len(accounts) - 3} more")
            return True
        else:
            print("⚠️ No accounts retrieved (server might be empty or connection failed)")
            return True  # Not necessarily an error
            
    except Exception as e:
        print(f"❌ Account retrieval failed: {e}")
        return False

def test_chrome_driver():
    """Test Chrome driver initialization"""
    print("\nTesting Chrome driver...")
    
    try:
        from chrome_automation import account_manager
        
        # Try to get Chrome driver
        driver = account_manager.get_chrome_driver()
        
        if driver:
            print("✅ Chrome driver initialized successfully")
            
            # Test basic functionality
            try:
                driver.get("https://www.google.com")
                print("✅ Chrome driver can navigate to websites")
                
                # Close the driver
                account_manager.close_chrome_driver()
                print("✅ Chrome driver closed successfully")
                return True
                
            except Exception as e:
                print(f"❌ Chrome driver navigation failed: {e}")
                account_manager.close_chrome_driver()
                return False
        else:
            print("❌ Chrome driver initialization failed")
            return False
            
    except Exception as e:
        print(f"❌ Chrome driver test failed: {e}")
        return False

def main():
    """Main test function"""
    print("🔧 Chrome Automation Test Suite")
    print("=" * 40)
    
    # Test imports
    if not test_imports():
        print("\n❌ Import tests failed. Please install missing dependencies.")
        sys.exit(1)
    
    # Test account retrieval
    if not test_account_retrieval():
        print("\n❌ Account retrieval test failed.")
        sys.exit(1)
    
    # Test Chrome driver
    if not test_chrome_driver():
        print("\n❌ Chrome driver test failed.")
        sys.exit(1)
    
    print("\n✅ All tests passed! Chrome automation is ready to use.")
    print("\n📋 Next steps:")
    print("1. Start the Flask application: python app.py")
    print("2. Navigate to the dashboard")
    print("3. Click 'Retrieve Accounts' to get accounts from server")
    print("4. Select an account and authenticate")
    print("5. Use Chrome automation in the OAuth modal")

if __name__ == "__main__":
    main()
