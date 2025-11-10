#!/usr/bin/env python3
"""
Database migration script to create DNS management tables
Run this script to add DNS functionality to existing GBot installations
"""

import os
import sys
from flask import Flask
from database import db, NamecheapConfig, DNSRecord, GoogleVerification

def create_dns_tables():
    """Create DNS management tables"""
    print("Creating DNS management tables...")
    
    app = Flask(__name__)
    app.config.from_object('config')
    db.init_app(app)
    
    with app.app_context():
        try:
            # Create all tables (will only create missing ones)
            db.create_all()
            
            print("✅ DNS tables created successfully!")
            print("Created tables:")
            print("  - namecheap_config (API configuration storage)")
            print("  - dns_record (DNS records history)")
            print("  - google_verification (Google Site Verification tracking)")
            
            # Check if tables were created
            inspector = db.inspect(db.engine)
            tables = inspector.get_table_names()
            
            dns_tables = ['namecheap_config', 'dns_record', 'google_verification']
            for table in dns_tables:
                if table in tables:
                    print(f"  ✅ {table} - exists")
                else:
                    print(f"  ❌ {table} - missing")
            
            print("\n🎉 DNS module database setup complete!")
            print("\nNext steps:")
            print("1. Configure Namecheap API credentials in .env file")
            print("2. Enable Google Site Verification API")
            print("3. Restart the GBot application")
            print("4. Access DNS Manager from the dashboard")
            
        except Exception as e:
            print(f"❌ Error creating DNS tables: {e}")
            return False
    
    return True

if __name__ == '__main__':
    if create_dns_tables():
        print("\n✅ Migration completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Migration failed!")
        sys.exit(1)