#!/usr/bin/env python3
"""
Fix used_domain table sequence issues causing duplicate key violations
This script addresses the specific error: duplicate key value violates unique constraint "used_domain_pkey"
"""

import sys
import os

# Add the app directory to Python path
sys.path.insert(0, '/opt/gbot-web-app')

print("=== Fixing used_domain Table Sequence Issues ===")

try:
    import app
    from database import db
    
    with app.app.app_context():
        print("1. Analyzing used_domain table...")
        
        # Check current max ID in used_domain table
        max_id_result = db.session.execute(db.text("SELECT MAX(id) FROM used_domain")).scalar()
        max_id = max_id_result if max_id_result is not None else 0
        print(f"   Current max ID in used_domain table: {max_id}")
        
        # Check current sequence value
        try:
            current_seq = db.session.execute(db.text("SELECT last_value FROM used_domain_id_seq")).scalar()
            print(f"   Current sequence value: {current_seq}")
        except Exception as e:
            print(f"   ⚠️  Sequence used_domain_id_seq doesn't exist: {e}")
            print("   Creating sequence...")
            db.session.execute(db.text("CREATE SEQUENCE used_domain_id_seq START 1"))
            db.session.commit()
            current_seq = 1
        
        print(f"\n2. Fixing sequence synchronization...")
        
        if current_seq <= max_id:
            # Fix the sequence to be one higher than max ID
            new_seq_value = max_id + 1
            print(f"   🔧 Setting sequence to: {new_seq_value}")
            
            db.session.execute(db.text(f"SELECT setval('used_domain_id_seq', {new_seq_value})"))
            db.session.commit()
            
            print(f"   ✅ used_domain sequence fixed")
        else:
            print(f"   ✅ used_domain sequence is already correct")
        
        # Also fix other related sequences that might have issues
        sequences_to_fix = [
            'user_id_seq',
            'whitelisted_ip_id_seq', 
            'google_account_id_seq',
            'google_token_id_seq',
            'scope_id_seq',
            'server_config_id_seq',
            'user_app_password_id_seq',
            'automation_account_id_seq',
            'retrieved_user_id_seq'
        ]
        
        print(f"\n3. Checking other related sequences...")
        
        for seq_name in sequences_to_fix:
            try:
                # Get table name from sequence name
                table_name = seq_name.replace('_id_seq', '')
                
                # Get current max ID
                max_id_result = db.session.execute(db.text(f"SELECT MAX(id) FROM {table_name}")).scalar()
                max_id = max_id_result if max_id_result is not None else 0
                
                # Get current sequence value
                current_seq = db.session.execute(db.text(f"SELECT last_value FROM {seq_name}")).scalar()
                
                if current_seq <= max_id:
                    new_seq_value = max_id + 1
                    print(f"   🔧 Fixing {seq_name}: setting to {new_seq_value}")
                    db.session.execute(db.text(f"SELECT setval('{seq_name}', {new_seq_value})"))
                    db.session.commit()
                    print(f"   ✅ {seq_name} fixed")
                else:
                    print(f"   ✅ {seq_name} is correct")
                    
            except Exception as e:
                print(f"   ⚠️  {seq_name}: {e}")
                continue
        
        print(f"\n4. Verifying all fixes...")
        
        # Verify used_domain sequence
        try:
            final_seq = db.session.execute(db.text("SELECT last_value FROM used_domain_id_seq")).scalar()
            final_max_id = db.session.execute(db.text("SELECT MAX(id) FROM used_domain")).scalar() or 0
            
            if final_seq > final_max_id:
                print(f"   ✅ used_domain: sequence {final_seq} > max_id {final_max_id}")
            else:
                print(f"   ⚠️  used_domain: sequence {final_seq} <= max_id {final_max_id}")
        except Exception as e:
            print(f"   ❌ used_domain verification failed: {e}")
        
        print(f"\n=== Database Sequence Fix Complete ===")
        print("✅ All sequences should now be properly synchronized")
        print("✅ The 'duplicate key value violates unique constraint' errors should be resolved")
        print("✅ You can now use the application without sequence conflicts")
        
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
