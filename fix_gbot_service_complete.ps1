# GBot Service Complete Fix Script (PowerShell)
# This script helps fix the 'gbot: unrecognized service' error on Linux servers

Write-Host "=== GBot Service Complete Fix Script ===" -ForegroundColor Blue
Write-Host "This script will help you fix the 'gbot: unrecognized service' error" -ForegroundColor Yellow
Write-Host ""

Write-Host "Please run these commands on your Ubuntu server:" -ForegroundColor Green
Write-Host ""

Write-Host "1. First, make the fix script executable:" -ForegroundColor Cyan
Write-Host "   chmod +x fix_gbot_service_complete.sh" -ForegroundColor White
Write-Host ""

Write-Host "2. Run the fix script as root:" -ForegroundColor Cyan
Write-Host "   sudo ./fix_gbot_service_complete.sh" -ForegroundColor White
Write-Host ""

Write-Host "3. If the script doesn't exist, create it manually:" -ForegroundColor Cyan
Write-Host "   sudo nano /opt/gbot-web-app/fix_gbot_service_complete.sh" -ForegroundColor White
Write-Host ""

Write-Host "4. Alternative: Create the service file manually:" -ForegroundColor Cyan
Write-Host "   sudo nano /etc/systemd/system/gbot.service" -ForegroundColor White
Write-Host ""

Write-Host "5. Service file content:" -ForegroundColor Cyan
Write-Host @"
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
ExecReload=/bin/kill -s HUP `$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=gbot

[Install]
WantedBy=multi-user.target
"@ -ForegroundColor White

Write-Host ""
Write-Host "6. After creating the service file:" -ForegroundColor Cyan
Write-Host "   sudo systemctl daemon-reload" -ForegroundColor White
Write-Host "   sudo systemctl enable gbot" -ForegroundColor White
Write-Host "   sudo systemctl start gbot" -ForegroundColor White
Write-Host "   sudo systemctl status gbot" -ForegroundColor White
Write-Host ""

Write-Host "7. Check logs if there are issues:" -ForegroundColor Cyan
Write-Host "   sudo journalctl -u gbot -f" -ForegroundColor White
Write-Host ""

Write-Host "8. Restart nginx if needed:" -ForegroundColor Cyan
Write-Host "   sudo systemctl restart nginx" -ForegroundColor White
Write-Host ""

Write-Host "=== Quick Commands Summary ===" -ForegroundColor Green
Write-Host "Check service status: sudo systemctl status gbot" -ForegroundColor White
Write-Host "View service logs:    sudo journalctl -u gbot -f" -ForegroundColor White
Write-Host "Restart service:      sudo systemctl restart gbot" -ForegroundColor White
Write-Host "Check nginx status:   sudo systemctl status nginx" -ForegroundColor White
Write-Host "Test nginx config:    sudo nginx -t" -ForegroundColor White
Write-Host ""

Write-Host "This should resolve the 'gbot: unrecognized service' error!" -ForegroundColor Green
