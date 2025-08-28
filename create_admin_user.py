#!/usr/bin/env python3
"""
Script to create admin user for GBot Web Application
"""

import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from database import User
from werkzeug.security import generate_password_hash

def create_admin_user():
    """Create admin user if it doesn't exist"""
    
    with app.app_context():
        print("🔍 Checking for admin user...")
        
        # Check if admin user exists
        admin_user = User.query.filter_by(username='admin').first()
        
        if admin_user:
            print("✅ Admin user already exists:")
            print(f"   Username: {admin_user.username}")
            print(f"   Role: {admin_user.role}")
            print(f"   ID: {admin_user.id}")
            return True
        else:
            print("❌ Admin user not found. Creating...")
            
            try:
                # Create admin user
                admin_user = User(
                    username='admin',
                    password=generate_password_hash('A9B3nX#Q8k$mZ6vw', method='pbkdf2:sha256'),
                    role='admin'
                )
                
                db.session.add(admin_user)
                db.session.commit()
                
                print("✅ Admin user created successfully!")
                print(f"   Username: admin")
                print(f"   Password: A9B3nX#Q8k$mZ6vw")
                print(f"   Role: admin")
                
                return True
                
            except Exception as e:
                print(f"❌ Error creating admin user: {e}")
                return False

def list_all_users():
    """List all users in the database"""
    
    with app.app_context():
        print("\n📋 All users in database:")
        users = User.query.all()
        
        if not users:
            print("   No users found")
        else:
            for user in users:
                print(f"   • {user.username} (Role: {user.role}, ID: {user.id})")

def test_login():
    """Test login with admin credentials"""
    
    with app.app_context():
        print("\n🔐 Testing login...")
        
        from werkzeug.security import check_password_hash
        
        admin_user = User.query.filter_by(username='admin').first()
        
        if not admin_user:
            print("❌ Admin user not found")
            return False
        
        # Test password
        if check_password_hash(admin_user.password, 'A9B3nX#Q8k$mZ6vw'):
            print("✅ Password verification successful")
            return True
        else:
            print("❌ Password verification failed")
            return False

if __name__ == '__main__':
    print("🚀 GBot Admin User Management")
    print("=" * 50)
    
    try:
        # Create admin user
        success = create_admin_user()
        
        if success:
            # List all users
            list_all_users()
            
            # Test login
            test_login()
            
            print("\n🎉 Admin user setup completed!")
            print("\n📝 Login credentials:")
            print("   Username: admin")
            print("   Password: A9B3nX#Q8k$mZ6vw")
            print("\n🌐 Access your application at: http://your-server-ip")
            
        else:
            print("\n❌ Failed to setup admin user")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
