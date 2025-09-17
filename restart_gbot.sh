#!/bin/bash

# GBot Web App Restart Script with Proper Timeout Configuration

echo "🔄 Restarting GBot Web Application with 10-minute timeout..."

# Stop the service
sudo systemctl stop gbot

# Wait a moment
sleep 2

# Copy the new service file
sudo cp gbot.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Start the service
sudo systemctl start gbot

# Enable auto-start
sudo systemctl enable gbot

# Check status
echo "📊 Service Status:"
sudo systemctl status gbot --no-pager

echo "✅ GBot Web Application restarted with 10-minute timeout!"
echo "🌐 Access your app at: http://your-server-ip:5000"
