#!/bin/bash

echo "🛡️ Enabling IP Whitelist Security..."

# Create backup of current .env
cp .env .env.backup.$(date +%Y%m%d_%H%M%S)

# Update .env file with secure settings
echo "📝 Updating .env file with secure IP whitelist settings..."

cat > .env << 'EOF'
# GBot Web Application Environment Configuration
# Generated automatically during installation

SECRET_KEY=08862b63441c97d83abad282487d56d3e4d3e297e3bb2b7a9ff9dee2ed917ffb
WHITELIST_TOKEN=4ee85e149031cac30f62f8ebb598f030
DATABASE_URL=postgresql://gbot_user:b6e1b027948143a398c5cd3e@localhost/gbot_db

# IP Whitelist Configuration - SECURITY ENABLED
ENABLE_IP_WHITELIST=True
ALLOW_ALL_IPS_IN_DEV=False

# Google API Configuration
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# Application Settings
DEBUG=False
FLASK_ENV=production
LOG_LEVEL=INFO

# Production Settings
SESSION_COOKIE_SECURE=False
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
PERMANENT_SESSION_LIFETIME=3600
EOF

echo "✅ .env file updated with secure settings"

# Activate virtual environment
source venv/bin/activate

# Set environment variables
export $(grep -v '^#' .env | xargs)

# Ensure we're using the PostgreSQL database URL
if [ -f ".db_credentials" ]; then
    source .db_credentials
    export DATABASE_URL
fi

# Get current IP address
CURRENT_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "unknown")

echo "🌐 Your current IP address: $CURRENT_IP"

# Add current IP to whitelist
echo "🔐 Adding your current IP to whitelist..."
python3 -c "
import os
from app import app, db
from database import WhitelistedIP

with app.app_context():
    # Check if IP already exists
    existing_ip = WhitelistedIP.query.filter_by(ip_address='$CURRENT_IP').first()
    
    if existing_ip:
        print(f'✅ IP $CURRENT_IP already in whitelist')
    else:
        # Add new IP
        new_ip = WhitelistedIP(ip_address='$CURRENT_IP')
        db.session.add(new_ip)
        db.session.commit()
        print(f'✅ IP $CURRENT_IP added to whitelist successfully')
    
    # List all whitelisted IPs
    print('\n📋 All whitelisted IPs:')
    whitelisted_ips = WhitelistedIP.query.all()
    if whitelisted_ips:
        for ip in whitelisted_ips:
            print(f'   • {ip.ip_address}')
    else:
        print('   No IPs whitelisted yet')
"

# Deactivate virtual environment
deactivate

# Restart the application
echo "🔄 Restarting application with IP whitelist enabled..."
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
echo "🛡️ IP Whitelist Security Enabled!"
echo ""
echo "📝 Security Settings:"
echo "   • ENABLE_IP_WHITELIST=True (IP whitelist enabled)"
echo "   • ALLOW_ALL_IPS_IN_DEV=False (no development bypass)"
echo "   • Your IP ($CURRENT_IP) added to whitelist"
echo ""
echo "🔐 Login credentials:"
echo "   Username: admin"
echo "   Password: A9B3nX#Q8k\$mZ6vw"
echo ""
echo "🌐 Access your application:"
echo "   Main app: http://172.235.163.73"
echo "   Whitelist management: http://172.235.163.73/whitelist"
echo ""
echo "⚠️  IMPORTANT SECURITY NOTES:"
echo "   • Only whitelisted IPs can access the application"
echo "   • Your current IP ($CURRENT_IP) is now whitelisted"
echo "   • To add more IPs, log in and go to whitelist management"
echo "   • Or use emergency access: http://172.235.163.73/emergency_access?key=4ee85e149031cac30f62f8ebb598f030"
echo ""
echo "🔧 To add more IPs:"
echo "   1. Log in from a whitelisted IP"
echo "   2. Go to: http://172.235.163.73/whitelist"
echo "   3. Add the new IP addresses"
echo ""
echo "🚨 SECURITY TEST:"
echo "   Try accessing from a different IP (like mobile data) - you should see 'Access denied'"
echo ""
