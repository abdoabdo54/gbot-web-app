#!/usr/bin/env python3
"""
Direct Namecheap API debugging script
Run this to test the exact API call being made
"""

import requests
import xml.etree.ElementTree as ET

def debug_namecheap_call():
    # Use your exact credentials
    api_user = "M2diafox"
    api_key = input("Enter your Namecheap API key: ").strip()
    username = "M2diafox"
    client_ip = "37.27.184.206"
    
    # Test URL
    base_url = "https://api.namecheap.com/xml.response"
    
    # Simple domain check (doesn't require account balance access)
    params = {
        'ApiUser': api_user,
        'ApiKey': api_key,
        'UserName': username,
        'ClientIp': client_ip,
        'Command': 'namecheap.domains.check',
        'DomainList': 'google.com'
    }
    
    print("Making API call with parameters:")
    for k, v in params.items():
        if k == 'ApiKey':
            print(f"  {k}: {'*' * len(v)}")
        else:
            print(f"  {k}: {v}")
    
    print(f"\nURL: {base_url}")
    
    try:
        response = requests.get(base_url, params=params, timeout=30)
        print(f"\nHTTP Status: {response.status_code}")
        print(f"Response Length: {len(response.content)} bytes")
        
        # Print raw response
        print(f"\nRaw Response:")
        print(response.text[:1000] + ('...' if len(response.text) > 1000 else ''))
        
        # Parse XML
        try:
            root = ET.fromstring(response.content)
            status = root.get('Status')
            print(f"\nAPI Status: {status}")
            
            if status != 'OK':
                errors = root.findall('.//Error')
                if errors:
                    print("Errors found:")
                    for error in errors:
                        error_num = error.get('Number', 'Unknown')
                        error_text = error.text or 'No error message'
                        print(f"  Error #{error_num}: {error_text}")
                else:
                    print("No specific errors found in response")
            else:
                # Check domain results
                results = root.findall('.//DomainCheckResult')
                print(f"Domain check results: {len(results)} found")
                for result in results:
                    domain = result.get('Domain')
                    available = result.get('Available')
                    print(f"  {domain}: Available = {available}")
        
        except ET.ParseError as e:
            print(f"\nXML Parse Error: {e}")
            
    except Exception as e:
        print(f"\nRequest Error: {e}")

if __name__ == "__main__":
    debug_namecheap_call()