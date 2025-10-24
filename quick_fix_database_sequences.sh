#!/bin/bash

echo "=== Quick Fix for Database Sequence Issues ==="
echo "This will fix the 'duplicate key value violates unique constraint' errors"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

echo "✅ Running as root"

# Navigate to app directory
cd /opt/gbot-web-app

echo ""
echo "1. Stopping GBot service temporarily..."
systemctl stop gbot

echo ""
echo "2. Running database sequence fix..."
python3 fix_used_domain_sequence.py

echo ""
echo "3. Also running comprehensive sequence fix..."
python3 fix_all_database_sequences.py

echo ""
echo "4. Restarting GBot service..."
systemctl start gbot

echo ""
echo "5. Waiting for service to start..."
sleep 5

echo ""
echo "6. Checking service status..."
systemctl status gbot --no-pager

echo ""
echo "7. Checking recent logs..."
journalctl -u gbot --no-pager -n 10

echo ""
echo "=== Fix Complete ==="
echo ""
echo "The database sequence issues should now be resolved."
echo "You should no longer see 'duplicate key value violates unique constraint' errors."
echo ""
echo "Monitor the logs with: sudo journalctl -u gbot -f"
