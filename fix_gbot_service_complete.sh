#!/bin/bash

echo "=== GBot Service Complete Fix Script ==="
echo "This script will fix the 'gbot: unrecognized service' error"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root (use sudo)"
    echo "Usage: sudo ./fix_gbot_service_complete.sh"
    exit 1
fi

echo "✅ Running as root"

# Set variables
APP_DIR="/opt/gbot-web-app"
SERVICE_FILE="/etc/systemd/system/gbot.service"
NGINX_CONFIG="/etc/nginx/sites-available/gbot"

echo ""
echo "1. Checking if application directory exists..."
if [ -d "$APP_DIR" ]; then
    echo "✅ Application directory found: $APP_DIR"
    cd "$APP_DIR"
else
    echo "❌ Application directory not found: $APP_DIR"
    echo "Please ensure the application is installed in /opt/gbot-web-app"
    exit 1
fi

echo ""
echo "2. Checking virtual environment..."
if [ -d "$APP_DIR/venv" ]; then
    echo "✅ Virtual environment exists"
else
    echo "❌ Virtual environment not found, creating..."
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    pip install gunicorn
    deactivate
fi

echo ""
echo "3. Installing/updating dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install gunicorn
deactivate

echo ""
echo "4. Creating systemd service file..."
cat > /tmp/gbot_service << 'EOF'
[Unit]
Description=GBot Web Application
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/gbot-web-app
Environment=PATH=/opt/gbot-web-app/venv/bin
ExecStart=/opt/gbot-web-app/venv/bin/gunicorn --bind unix:/opt/gbot-web-app/gbot.sock --workers 4 --timeout 300 --keep-alive 2 --max-requests 1000 --max-requests-jitter 100 --preload app:app
ExecReload=/bin/kill -s HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=gbot

[Install]
WantedBy=multi-user.target
EOF

# Copy service file
cp /tmp/gbot_service "$SERVICE_FILE"
rm /tmp/gbot_service

echo "✅ Service file created: $SERVICE_FILE"

echo ""
echo "5. Setting proper permissions..."
chmod 644 "$SERVICE_FILE"
chown root:root "$SERVICE_FILE"

echo ""
echo "6. Reloading systemd daemon..."
systemctl daemon-reload

echo ""
echo "7. Enabling service..."
systemctl enable gbot

echo ""
echo "8. Stopping any existing service..."
systemctl stop gbot 2>/dev/null || true

echo ""
echo "9. Removing old socket file..."
rm -f "$APP_DIR/gbot.sock"

echo ""
echo "10. Starting GBot service..."
systemctl start gbot

echo ""
echo "11. Waiting for service to start..."
sleep 5

echo ""
echo "12. Checking service status..."
systemctl status gbot --no-pager

echo ""
echo "13. Checking service logs..."
echo "Recent logs:"
journalctl -u gbot --no-pager -n 20

echo ""
echo "14. Testing application..."
if systemctl is-active --quiet gbot; then
    echo "✅ GBot service is running!"
    
    # Check if socket file exists
    if [ -S "$APP_DIR/gbot.sock" ]; then
        echo "✅ Socket file created: $APP_DIR/gbot.sock"
    else
        echo "⚠️  Socket file not found, but service is running"
    fi
    
    # Check nginx configuration
    if [ -f "$NGINX_CONFIG" ]; then
        echo "✅ Nginx configuration exists"
        echo "Testing nginx configuration..."
        nginx -t
        if [ $? -eq 0 ]; then
            echo "✅ Nginx configuration is valid"
            echo "Reloading nginx..."
            systemctl reload nginx
        else
            echo "❌ Nginx configuration has errors"
        fi
    else
        echo "⚠️  Nginx configuration not found: $NGINX_CONFIG"
    fi
    
else
    echo "❌ GBot service failed to start"
    echo "Checking logs for errors..."
    journalctl -u gbot --no-pager -n 50
    exit 1
fi

echo ""
echo "=== Fix Complete ==="
echo ""
echo "Service commands:"
echo "  Check status: sudo systemctl status gbot"
echo "  View logs:    sudo journalctl -u gbot -f"
echo "  Restart:      sudo systemctl restart gbot"
echo "  Stop:         sudo systemctl stop gbot"
echo "  Start:        sudo systemctl start gbot"
echo ""
echo "If you still get 502 errors, check:"
echo "  1. sudo systemctl status gbot"
echo "  2. sudo journalctl -u gbot -f"
echo "  3. sudo systemctl status nginx"
echo "  4. Check nginx configuration: sudo nginx -t"
