#!/usr/bin/env python3
"""
Unified fix for app password storage and retrieval consistency
This ensures both upload and automation processes use the same database and logic
"""

import sys
import os

# Add the app directory to Python path
sys.path.insert(0, '/opt/gbot-web-app')

print("=== Unified App Password Fix ===")

try:
    import app
    from database import UserAppPassword, db
    
    with app.app.app_context():
        print("1. Analyzing current app password storage...")
        
        # Get all app passwords
        all_passwords = UserAppPassword.query.all()
        total_count = len(all_passwords)
        print(f"Total app passwords in database: {total_count}")
        
        if total_count == 0:
            print("❌ No app passwords found in database")
            print("This explains why the UI shows 0 count")
            print("Please upload app passwords first using the 'Upload & Store Passwords' button")
            return
        
        print("\n2. Checking for storage inconsistencies...")
        
        # Check if passwords are actually stored
        passwords_with_data = [pwd for pwd in all_passwords if pwd.app_password]
        print(f"Passwords with actual data: {len(passwords_with_data)}")
        
        if len(passwords_with_data) == 0:
            print("⚠️  All records exist but have no password data!")
            print("This might be a database schema issue")
            
            # Check the first few records
            print("\nSample records:")
            for i, pwd in enumerate(all_passwords[:3], 1):
                print(f"  {i}. Username: '{pwd.username}', Domain: '{pwd.domain}'")
                print(f"     Password field: '{pwd.app_password}'")
                print(f"     Created: {pwd.created_at}")
                print(f"     Updated: {pwd.updated_at}")
        else:
            print("✅ Passwords have data")
            
            # Show sample data
            print("\nSample passwords:")
            for i, pwd in enumerate(passwords_with_data[:3], 1):
                print(f"  {i}. {pwd.username}@{pwd.domain} -> {pwd.app_password[:5]}...")
        
        print("\n3. Testing the automation matching logic...")
        
        # Test the exact same logic used in automation process
        test_emails = [
            'support@jrvdtowwentksfbk.glize.com',
            'alberto@alberto.amasahistoricalsociety.space',
            'administrator@jptkbfio4dyslcaf.accesscam.org'
        ]
        
        matches_found = 0
        for email in test_emails:
            print(f"\n  Testing: {email}")
            username, domain = email.split('@', 1)
            username = username.strip().lower()
            domain = domain.strip().lower()
            
            # Use the exact same logic as in api_execute_automation_process
            app_password_record = UserAppPassword.query.filter(
                db.func.lower(UserAppPassword.username) == username,
                db.func.lower(UserAppPassword.domain) == domain
            ).first()
            
            if app_password_record and app_password_record.app_password:
                matches_found += 1
                print(f"    ✅ Match found: {app_password_record.app_password[:5]}...")
            else:
                print(f"    ❌ No match found")
                
                # Debug: show what's actually in the database for this domain
                domain_records = UserAppPassword.query.filter_by(domain=domain).all()
                if domain_records:
                    print(f"    📋 Records for domain '{domain}':")
                    for record in domain_records:
                        print(f"      - {record.username}@{record.domain} -> {record.app_password[:5] if record.app_password else 'NO PASSWORD'}...")
                else:
                    print(f"    📋 No records for domain '{domain}'")
                    
                    # Check for similar domains
                    similar = UserAppPassword.query.filter(
                        UserAppPassword.domain.like(f'%{domain.split(".")[-1]}%')
                    ).all()
                    if similar:
                        print(f"    📋 Similar domains found:")
                        for record in similar:
                            print(f"      - {record.username}@{record.domain}")
        
        print(f"\n4. Summary:")
        print(f"  - Total passwords in database: {total_count}")
        print(f"  - Passwords with data: {len(passwords_with_data)}")
        print(f"  - Test matches found: {matches_found}/{len(test_emails)}")
        
        if matches_found > 0:
            print("✅ The automation process should be able to find app passwords")
            print("   The issue might be in the frontend display or API response")
        else:
            print("❌ The automation process cannot find app passwords")
            print("   This explains why automation shows 'No app password'")
        
        print("\n5. Recommendations:")
        if total_count == 0:
            print("  - Upload app passwords using the 'Upload & Store Passwords' button")
        elif len(passwords_with_data) == 0:
            print("  - Check the upload process - passwords are not being stored with data")
        elif matches_found == 0:
            print("  - Check domain/username matching - the automation process cannot find stored passwords")
        else:
            print("  - The system should be working correctly")
            print("  - If UI still shows 0, check the frontend JavaScript and API responses")
        
        print("\n=== Analysis Complete ===")
        
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
