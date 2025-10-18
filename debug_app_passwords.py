#!/usr/bin/env python3
"""
Debug script to check app password storage and retrieval consistency
"""

import sys
import os

# Add the app directory to Python path
sys.path.insert(0, '/opt/gbot-web-app')

print("=== App Password Debug Script ===")

try:
    import app
    from database import UserAppPassword, db
    
    print("1. Testing database connection...")
    with app.app.app_context():
        # Get total count
        total_count = UserAppPassword.query.count()
        print(f"✅ Total app passwords in database: {total_count}")
        
        if total_count > 0:
            print("\n2. Sample app passwords:")
            sample_passwords = UserAppPassword.query.limit(10).all()
            for i, pwd in enumerate(sample_passwords, 1):
                print(f"  {i}. {pwd.username}@{pwd.domain} -> {pwd.app_password[:5]}..." if pwd.app_password else "  {i}. {pwd.username}@{pwd.domain} -> (no password)")
            
            print("\n3. Checking for specific domains...")
            domains = ['jrvdtowwentksfbk.glize.com', 'alberto.amasahistoricalsociety.space', 'jptkbfio4dyslcaf.accesscam.org']
            
            for domain in domains:
                count = UserAppPassword.query.filter_by(domain=domain).count()
                print(f"  Domain '{domain}': {count} passwords")
                
                if count > 0:
                    passwords = UserAppPassword.query.filter_by(domain=domain).all()
                    for pwd in passwords:
                        print(f"    - {pwd.username}@{pwd.domain}")
            
            print("\n4. Checking for admin/administrator accounts...")
            admin_accounts = UserAppPassword.query.filter(
                db.func.lower(UserAppPassword.username).in_(['admin', 'administrator', 'support'])
            ).all()
            
            print(f"  Found {len(admin_accounts)} admin accounts:")
            for pwd in admin_accounts:
                print(f"    - {pwd.username}@{pwd.domain}")
            
            print("\n5. Testing app password retrieval logic...")
            # Test the same logic used in automation process
            test_emails = [
                'support@jrvdtowwentksfbk.glize.com',
                'alberto@alberto.amasahistoricalsociety.space', 
                'administrator@jptkbfio4dyslcaf.accesscam.org'
            ]
            
            for email in test_emails:
                print(f"\n  Testing email: {email}")
                username, domain = email.split('@', 1)
                username = username.strip().lower()
                domain = domain.strip().lower()
                
                # Strategy 1: Exact match
                exact_match = UserAppPassword.query.filter_by(
                    username=username, 
                    domain=domain
                ).first()
                
                if exact_match:
                    print(f"    ✅ Exact match found: {exact_match.app_password[:5]}...")
                else:
                    # Strategy 2: Case-insensitive exact match
                    case_insensitive = UserAppPassword.query.filter(
                        db.func.lower(UserAppPassword.username) == username,
                        db.func.lower(UserAppPassword.domain) == domain
                    ).first()
                    
                    if case_insensitive:
                        print(f"    ✅ Case-insensitive match found: {case_insensitive.app_password[:5]}...")
                    else:
                        print(f"    ❌ No match found for {email}")
                        
                        # Show what's actually in the database for this domain
                        domain_records = UserAppPassword.query.filter_by(domain=domain).all()
                        if domain_records:
                            print(f"    📋 Records for domain '{domain}':")
                            for record in domain_records:
                                print(f"      - {record.username}@{record.domain}")
                        else:
                            print(f"    📋 No records found for domain '{domain}'")
                            
                            # Check if there are any records with similar domains
                            similar_domains = UserAppPassword.query.filter(
                                UserAppPassword.domain.like(f'%{domain.split(".")[-1]}%')
                            ).all()
                            if similar_domains:
                                print(f"    📋 Similar domains found:")
                                for record in similar_domains:
                                    print(f"      - {record.username}@{record.domain}")
        
        else:
            print("❌ No app passwords found in database")
            
        print("\n=== Debug Complete ===")
        
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
