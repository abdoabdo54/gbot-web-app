#!/usr/bin/env python3
"""
Fix script to ensure app password upload and automation processes use the same storage/retrieval logic
"""

import sys
import os

# Add the app directory to Python path
sys.path.insert(0, '/opt/gbot-web-app')

print("=== App Password Consistency Fix ===")

try:
    import app
    from database import UserAppPassword, db
    
    with app.app.app_context():
        print("1. Checking current app password storage...")
        total_count = UserAppPassword.query.count()
        print(f"Total app passwords: {total_count}")
        
        if total_count > 0:
            print("\n2. Analyzing storage patterns...")
            
            # Check for any inconsistencies in username/domain storage
            all_passwords = UserAppPassword.query.all()
            
            print("Sample records:")
            for i, pwd in enumerate(all_passwords[:5], 1):
                print(f"  {i}. Username: '{pwd.username}', Domain: '{pwd.domain}', Has Password: {bool(pwd.app_password)}")
            
            # Check for case sensitivity issues
            case_issues = []
            for pwd in all_passwords:
                if pwd.username != pwd.username.lower() or pwd.domain != pwd.domain.lower():
                    case_issues.append(f"{pwd.username}@{pwd.domain}")
            
            if case_issues:
                print(f"\n⚠️  Found {len(case_issues)} case sensitivity issues:")
                for issue in case_issues[:5]:  # Show first 5
                    print(f"  - {issue}")
            
            print("\n3. Normalizing all records to lowercase...")
            normalized_count = 0
            
            for pwd in all_passwords:
                original_username = pwd.username
                original_domain = pwd.domain
                
                # Normalize to lowercase
                pwd.username = pwd.username.lower()
                pwd.domain = pwd.domain.lower()
                
                if original_username != pwd.username or original_domain != pwd.domain:
                    normalized_count += 1
                    print(f"  Normalized: {original_username}@{original_domain} -> {pwd.username}@{pwd.domain}")
            
            if normalized_count > 0:
                db.session.commit()
                print(f"✅ Normalized {normalized_count} records")
            else:
                print("✅ All records already normalized")
            
            print("\n4. Checking for duplicate records...")
            # Find duplicates after normalization
            duplicates = db.session.execute(db.text("""
                SELECT username, domain, COUNT(*) as count
                FROM user_app_password 
                GROUP BY username, domain 
                HAVING COUNT(*) > 1
            """)).fetchall()
            
            if duplicates:
                print(f"⚠️  Found {len(duplicates)} duplicate records:")
                for dup in duplicates:
                    print(f"  - {dup.username}@{dup.domain} ({dup.count} copies)")
                
                # Remove duplicates, keeping the first one
                print("Removing duplicates...")
                for dup in duplicates:
                    # Get all records for this username/domain
                    records = UserAppPassword.query.filter_by(
                        username=dup.username,
                        domain=dup.domain
                    ).all()
                    
                    # Keep the first one, delete the rest
                    for record in records[1:]:
                        db.session.delete(record)
                        print(f"    Deleted duplicate: {record.username}@{record.domain}")
                
                db.session.commit()
                print("✅ Duplicates removed")
            else:
                print("✅ No duplicate records found")
            
            print("\n5. Final verification...")
            final_count = UserAppPassword.query.count()
            print(f"Final app password count: {final_count}")
            
            # Test the automation matching logic
            print("\n6. Testing automation matching logic...")
            test_emails = [
                'support@jrvdtowwentksfbk.glize.com',
                'alberto@alberto.amasahistoricalsociety.space',
                'administrator@jptkbfio4dyslcaf.accesscam.org'
            ]
            
            for email in test_emails:
                print(f"\n  Testing: {email}")
                username, domain = email.split('@', 1)
                username = username.strip().lower()
                domain = domain.strip().lower()
                
                # Use the same logic as automation process
                match = UserAppPassword.query.filter(
                    db.func.lower(UserAppPassword.username) == username,
                    db.func.lower(UserAppPassword.domain) == domain
                ).first()
                
                if match:
                    print(f"    ✅ Match found: {match.app_password[:5]}...")
                else:
                    print(f"    ❌ No match found")
                    
                    # Check what's actually stored for this domain
                    domain_records = UserAppPassword.query.filter_by(domain=domain).all()
                    if domain_records:
                        print(f"    📋 Records for domain '{domain}':")
                        for record in domain_records:
                            print(f"      - {record.username}@{record.domain}")
                    else:
                        print(f"    📋 No records for domain '{domain}'")
            
            print("\n=== Consistency Fix Complete ===")
            print("✅ App password storage and retrieval should now be consistent")
            
        else:
            print("❌ No app passwords found in database")
            print("Please upload some app passwords first")
            
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
