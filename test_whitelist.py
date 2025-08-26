#!/usr/bin/env python3
"""
Test script to debug IP whitelist configuration
"""
import os
import requests
import json

def test_config():
    """Test the configuration values"""
    print("=== Testing Configuration ===")
    
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    print(f"WHITELIST_TOKEN: {os.environ.get('WHITELIST_TOKEN', 'None')}")
    print(f"ENABLE_IP_WHITELIST: {os.environ.get('ENABLE_IP_WHITELIST', 'None')}")
    print(f"DEBUG: {os.environ.get('DEBUG', 'None')}")
    print(f"SECRET_KEY: {os.environ.get('SECRET_KEY', 'None')}")
    
    # Test config.py
    try:
        import config
        print(f"\nConfig.py values:")
        print(f"WHITELIST_TOKEN: {config.WHITELIST_TOKEN}")
        print(f"ENABLE_IP_WHITELIST: {config.ENABLE_IP_WHITELIST}")
        print(f"DEBUG: {config.DEBUG}")
    except Exception as e:
        print(f"Error loading config: {e}")

def test_api_endpoints(base_url):
    """Test the API endpoints"""
    print(f"\n=== Testing API Endpoints ===")
    
    # Test debug config endpoint
    try:
        response = requests.get(f"{base_url}/api/debug-config", timeout=10)
        if response.status_code == 200:
            config_data = response.json()
            print(f"Debug config endpoint: {json.dumps(config_data, indent=2)}")
        else:
            print(f"Debug config endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"Error testing debug config: {e}")
    
    # Test emergency access endpoint
    try:
        response = requests.get(f"{base_url}/emergency_access", timeout=10)
        if response.status_code == 200:
            print(f"Emergency access endpoint: OK (200)")
        else:
            print(f"Emergency access endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"Error testing emergency access: {e}")

def test_emergency_add_ip(base_url, ip_address, emergency_key):
    """Test the emergency add IP endpoint"""
    print(f"\n=== Testing Emergency Add IP ===")
    
    try:
        data = {
            'ip_address': ip_address,
            'emergency_key': emergency_key
        }
        
        response = requests.post(
            f"{base_url}/api/emergency-add-ip",
            json=data,
            timeout=10
        )
        
        print(f"Status code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Success: {result.get('success')}")
            if not result.get('success'):
                print(f"Error: {result.get('error')}")
        
    except Exception as e:
        print(f"Error testing emergency add IP: {e}")

if __name__ == '__main__':
    # Test configuration
    test_config()
    
    # Test API endpoints (change this to your actual domain)
    base_url = "https://ecochain.site"
    
    # Test emergency add IP (change these values)
    ip_address = "102.101.242.72"  # Your current IP
    emergency_key = "4cb5d7420abd8b144be9c79723905d5d"  # Your WHITELIST_TOKEN
    
    test_api_endpoints(base_url)
    test_emergency_add_ip(base_url, ip_address, emergency_key)
