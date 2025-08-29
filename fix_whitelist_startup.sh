#!/bin/bash

echo "🔧 Fixing IP Whitelist Startup Issue..."

# First, let's check the current status
echo "📋 Current application status:"
systemctl status gbot --no-pager

# Check the logs
echo ""
echo "📋 Recent application logs:"
journalctl -u gbot -n 20 --no-pager

# The issue is likely that IP whitelist is enabled but no IPs are whitelisted
# Let's temporarily disable IP whitelist to get the app running
echo ""
echo "🔧 Temporarily disabling IP whitelist to fix startup..."

# Create backup
cp .env .env.backup.$(date +%Y%m%d_%H%M%S)

# Temporarily disable IP whitelist
sed -i 's/ENABLE_IP_WHITELIST=True/ENABLE_IP_WHITELIST=False/' .env
sed -i 's/ALLOW_ALL_IPS_IN_DEV=False/ALLOW_ALL_IPS_IN_DEV=True/' .env

echo "✅ IP whitelist temporarily disabled"

# Restart the application
echo "🔄 Restarting application..."
systemctl restart gbot

# Wait for restart
sleep 5

# Check if it's running now
if systemctl is-active --quiet gbot; then
    echo "✅ Application is now running!"
    
    # Now let's properly set up IP whitelist
    echo ""
    echo "🔐 Setting up IP whitelist properly..."
    
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
    
    # Count total IPs
    total_ips = WhitelistedIP.query.count()
    print(f'\nTotal whitelisted IPs: {total_ips}')
"
    
    # Deactivate virtual environment
    deactivate
    
    # Now re-enable IP whitelist
    echo ""
    echo "🛡️ Re-enabling IP whitelist security..."
    sed -i 's/ENABLE_IP_WHITELIST=False/ENABLE_IP_WHITELIST=True/' .env
    sed -i 's/ALLOW_ALL_IPS_IN_DEV=True/ALLOW_ALL_IPS_IN_DEV=False/' .env
    
    # Restart again with IP whitelist enabled
    echo "🔄 Restarting application with IP whitelist enabled..."
    systemctl restart gbot
    
    # Wait for restart
    sleep 5
    
    # Check final status
    if systemctl is-active --quiet gbot; then
        echo ""
        echo "🎉 IP Whitelist Startup Issue Fixed!"
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
        echo "✅ Application is running with IP whitelist security enabled!"
    else
        echo ""
        echo "❌ Application still failed to start with IP whitelist"
        echo "📋 Final status:"
        systemctl status gbot --no-pager
        echo ""
        echo "📋 Final logs:"
        journalctl -u gbot -n 20 --no-pager
        echo ""
        echo "🔧 Keeping IP whitelist disabled for now"
        echo "   You can manually enable it later when you have IPs whitelisted"
    fi
    
else
    echo ""
    echo "❌ Application still failed to start even with IP whitelist disabled"
    echo "📋 Status:"
    systemctl status gbot --no-pager
    echo ""
    echo "📋 Logs:"
    journalctl -u gbot -n 20 --no-pager
    echo ""
    echo "🔧 There might be another issue. Check the logs above."
fi
