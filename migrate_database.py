#!/usr/bin/env python3
"""
Database Migration Script for GBot Web App
Adds new columns and tables for domain change tracking and server settings
"""

import os
import sys
from datetime import datetime

# Add the app directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from database import UsedDomain, ServerSettings

def run_migration():
    """Run database migration"""
    print("🔄 Starting database migration...")
    
    with app.app_context():
        try:
            # Check if new columns exist in UsedDomain
            print("📊 Checking UsedDomain table...")
            
            # Try to add new columns to UsedDomain
            try:
                db.engine.execute("""
                    ALTER TABLE used_domain 
                    ADD COLUMN last_domain_change TIMESTAMP NULL,
                    ADD COLUMN changed_by_account VARCHAR(255) NULL
                """)
                print("✅ Added last_domain_change and changed_by_account columns to UsedDomain")
            except Exception as e:
                if "already exists" in str(e).lower() or "duplicate column" in str(e).lower():
                    print("ℹ️ Columns already exist in UsedDomain table")
                else:
                    print(f"⚠️ Error adding columns to UsedDomain: {e}")
            
            # Check if ServerSettings table exists
            print("⚙️ Checking ServerSettings table...")
            
            # Create ServerSettings table
            try:
                db.engine.execute("""
                    CREATE TABLE server_settings (
                        id SERIAL PRIMARY KEY,
                        server_host VARCHAR(255) NOT NULL,
                        server_port INTEGER DEFAULT 22,
                        server_username VARCHAR(255) NOT NULL,
                        server_password TEXT NULL,
                        server_key_path VARCHAR(500) NULL,
                        json_files_path VARCHAR(500) NOT NULL DEFAULT '/opt/gbot-web-app/accounts/',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                print("✅ Created ServerSettings table")
            except Exception as e:
                if "already exists" in str(e).lower() or "duplicate table" in str(e).lower():
                    print("ℹ️ ServerSettings table already exists")
                else:
                    print(f"⚠️ Error creating ServerSettings table: {e}")
            
            print("🎉 Database migration completed successfully!")
            
        except Exception as e:
            print(f"❌ Migration failed: {e}")
            return False
    
    return True

if __name__ == "__main__":
    success = run_migration()
    sys.exit(0 if success else 1)
