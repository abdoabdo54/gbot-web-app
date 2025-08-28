#!/bin/bash

# Quick fix for admin login issue
echo "🔧 Fixing admin login issue..."

# Activate virtual environment
source venv/bin/activate

# Set environment variables
export $(grep -v '^#' .env | xargs)

# Ensure we're using the PostgreSQL database URL
if [ -f ".db_credentials" ]; then
    source .db_credentials
    export DATABASE_URL
fi

# Create admin user
echo "Creating admin user..."
python3 -c "
import os
from app import app, db
from database import User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Check if admin user exists
    admin_user = User.query.filter_by(username='admin').first()
    
    if admin_user:
        print('✅ Admin user already exists')
        print(f'Username: {admin_user.username}')
        print(f'Role: {admin_user.role}')
    else:
        print('❌ Admin user not found. Creating...')
        
        # Create admin user
        admin_user = User(
            username='admin',
            password=generate_password_hash('A9B3nX#Q8k\$mZ6vw', method='pbkdf2:sha256'),
            role='admin'
        )
        
        db.session.add(admin_user)
        db.session.commit()
        
        print('✅ Admin user created successfully!')
        print('Username: admin')
        print('Password: A9B3nX#Q8k\$mZ6vw')
        print('Role: admin')
    
    # List all users
    print('\n📋 All users in database:')
    users = User.query.all()
    for user in users:
        print(f'  • {user.username} (Role: {user.role}, ID: {user.id})')
"

# Deactivate virtual environment
deactivate

# Restart the application
echo "Restarting application..."
systemctl restart gbot

# Wait for restart
sleep 3

# Check status
if systemctl is-active --quiet gbot; then
    echo "✅ Application restarted successfully"
else
    echo "❌ Application restart failed"
    systemctl status gbot
fi

echo ""
echo "🎉 Admin user fix completed!"
echo ""
echo "📝 Login credentials:"
echo "   Username: admin"
echo "   Password: A9B3nX#Q8k\$mZ6vw"
echo ""
echo "🌐 Try logging in at: http://172.235.163.73"
echo ""
