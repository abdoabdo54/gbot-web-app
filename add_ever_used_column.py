#!/usr/bin/env python3
"""
Simple database migration to add ever_used column to used_domain table
"""

import os
import sys
import psycopg2
from urllib.parse import urlparse

def get_db_connection():
    """Get database connection from environment or config"""
    try:
        # Try to get from environment first
        database_url = os.getenv('DATABASE_URL')
        if database_url:
            url = urlparse(database_url)
            return psycopg2.connect(
                host=url.hostname,
                port=url.port,
                database=url.path[1:],
                user=url.username,
                password=url.password
            )
        
        # Fallback to config.py
        try:
            import config
            if hasattr(config, 'SQLALCHEMY_DATABASE_URI'):
                url = urlparse(config.SQLALCHEMY_DATABASE_URI)
                return psycopg2.connect(
                    host=url.hostname,
                    port=url.port or 5432,
                    database=url.path[1:] if url.path else 'postgres',
                    user=url.username or 'postgres',
                    password=url.password or ''
                )
        except:
            pass
        
        # Default connection
        return psycopg2.connect(
            host='localhost',
            port=5432,
            database='postgres',
            user='postgres',
            password=''
        )
    except Exception as e:
        print(f"❌ Could not connect to database: {e}")
        return None

def add_ever_used_column():
    """Add ever_used column to used_domain table"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        # Check if column already exists
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'used_domain' AND column_name = 'ever_used'
        """)
        
        if cursor.fetchone():
            print("✅ Column 'ever_used' already exists in used_domain table")
            return True
        
        print("🔄 Adding 'ever_used' column to used_domain table...")
        
        # Add the column
        cursor.execute("""
            ALTER TABLE used_domain 
            ADD COLUMN ever_used BOOLEAN DEFAULT FALSE
        """)
        
        # Update existing records: if user_count > 0, set ever_used = TRUE
        cursor.execute("""
            UPDATE used_domain 
            SET ever_used = TRUE 
            WHERE user_count > 0
        """)
        
        rows_updated = cursor.rowcount
        
        conn.commit()
        
        print(f"✅ Successfully added 'ever_used' column!")
        print(f"   - Updated {rows_updated} existing records with ever_used=TRUE")
        
        # Show current status
        cursor.execute("SELECT COUNT(*) FROM used_domain")
        total = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM used_domain WHERE ever_used = TRUE")
        ever_used_count = cursor.fetchone()[0]
        
        print(f"   - Total domains: {total}")
        print(f"   - Ever used domains: {ever_used_count}")
        print(f"   - Available domains: {total - ever_used_count}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error adding column: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    print("🔄 Starting database migration to add 'ever_used' column...")
    success = add_ever_used_column()
    
    if success:
        print("🎉 Migration completed successfully!")
        sys.exit(0)
    else:
        print("💥 Migration failed!")
        sys.exit(1)
