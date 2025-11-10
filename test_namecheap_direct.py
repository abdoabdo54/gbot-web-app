#!/usr/bin/env python3
"""
Simple direct test of Namecheap API - run this to debug the issue
"""

import requests
import xml.etree.ElementTree as ET

# Your exact credentials from the error message
API_USER = "M2diafox"
USERNAME = "M2diafox"
CLIENT_IP = "37.27.184.206"

def test_namecheap_api_key(api_key):
    """Test with your actual API key"""
    
    print(f"Testing Namecheap API with:")
    print(f"  API User: {API_USER}")
    print(f"  Username: {USERNAME}")
    print(f"  Client IP: {CLIENT_IP}")
    print(f"  API Key: {'*' * len(api_key)}")
    print()
    
    # Use the simplest possible API call
    url = "https://api.namecheap.com/xml.response"
    
    params = {
        'ApiUser': API_USER,
        'ApiKey': api_key,
        'UserName': USERNAME,
        'ClientIp': CLIENT_IP,
        'Command': 'namecheap.domains.check',
        'DomainList': 'test.com'
    }
    
    try:
        print("Making API request...")
        response = requests.get(url, params=params, timeout=30)
        
        print(f"HTTP Status Code: {response.status_code}")
        print()
        
        if response.status_code == 200:
            print("Raw XML Response:")
            print("-" * 50)
            print(response.text)
            print("-" * 50)
            print()
            
            # Parse XML
            try:
                root = ET.fromstring(response.content)
                status = root.get('Status')
                print(f"Namecheap API Status: {status}")
                
                if status == 'ERROR':
                    print("\nERROR DETAILS:")
                    errors = root.findall('.//Error')
                    for i, error in enumerate(errors, 1):
                        error_num = error.get('Number', 'Unknown')
                        error_text = error.text or 'No message'
                        print(f"  Error #{i}: Number={error_num}, Message='{error_text}'")
                
                elif status == 'OK':
                    print("\nSUCCESS! API is working.")
                    results = root.findall('.//DomainCheckResult')
                    print(f"Found {len(results)} domain check results")
                    
            except ET.ParseError as e:
                print(f"XML Parse Error: {e}")
                
        else:
            print(f"HTTP Error: {response.status_code}")
            print(response.text)
            
    except Exception as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    print("=== Namecheap API Direct Test ===")
    print()
    
    api_key = input("Enter your Namecheap API key: ").strip()
    if api_key:
        test_namecheap_api_key(api_key)
    else:
        print("No API key provided")