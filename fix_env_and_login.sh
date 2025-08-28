#!/bin/bash

echo "🔧 Fixing environment settings and login issue..."

# Fix the .env file
echo "📝 Updating .env file..."

# Create a backup
cp .env .env.backup

# Update the .env file with correct settings
cat > .env << 'EOF'
# GBot Web Application Environment Configuration
# Generated automatically during installation

SECRET_KEY=08862b63441c97d83abad282487d56d3e4d3e297e3bb2b7a9ff9dee2ed917ffb
WHITELIST_TOKEN=4ee85e149031cac30f62f8ebb598f030
DATABASE_URL=postgresql://gbot_user:b6e1b027948143a398c5cd3e@localhost/gbot_db

# IP Whitelist Configuration
ENABLE_IP_WHITELIST=False
ALLOW_ALL_IPS_IN_DEV=True

# Google API Configuration
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# Application Settings
DEBUG=False
FLASK_ENV=production
LOG_LEVEL=INFO

# Production Settings - FIXED FOR HTTP ACCESS
SESSION_COOKIE_SECURE=False
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
PERMANENT_SESSION_LIFETIME=3600
EOF

echo "✅ .env file updated"

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
echo "🔐 Creating admin user..."
python3 -c "
import os
from app import app, db
from database import User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Check if admin user exists
    admin_user = User.query.filter_by(username='admin').first()
    
    if admin_user:
        print('✅ Admin user already exists:')
        print(f'   Username: {admin_user.username}')
        print(f'   Role: {admin_user.role}')
        print(f'   ID: {admin_user.id}')
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
        print('   Username: admin')
        print('   Password: A9B3nX#Q8k\$mZ6vw')
        print('   Role: admin')
    
    # List all users
    print('\n📋 All users in database:')
    users = User.query.all()
    for user in users:
        print(f'   • {user.username} (Role: {user.role}, ID: {user.id})')
"

# Deactivate virtual environment
deactivate

# Restart the application
echo "🔄 Restarting application..."
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
echo "🎉 Environment and login fix completed!"
echo ""
echo "📝 Updated settings:"
echo "   • SESSION_COOKIE_SECURE=False (allows HTTP access)"
echo "   • ENABLE_IP_WHITELIST=False (IP whitelist disabled)"
echo "   • Admin user created/verified"
echo ""
echo "🔐 Login credentials:"
echo "   Username: admin"
echo "   Password: A9B3nX#Q8k\$mZ6vw"
echo ""
echo "🌐 Access your application:"
echo "   Main app: http://172.235.163.73"
echo "   Test admin: http://172.235.163.73/test-admin"
echo "   Emergency access: http://172.235.163.73/emergency_access"
echo ""
echo "🔧 For whitelist management:"
echo "   1. First log in with admin credentials"
echo "   2. Then access: http://172.235.163.73/whitelist"
echo "   3. Or use emergency access with your WHITELIST_TOKEN"
echo ""
