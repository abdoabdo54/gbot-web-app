#!/bin/bash

# Exit on any error
set -e

# 1. System Update and Dependencies
echo "Updating and installing system dependencies..."
sudo apt-get update
sudo apt-get install -y python3-pip python3-dev build-essential libssl-dev libffi-dev python3-setuptools
sudo apt-get install -y python3-venv
sudo apt-get install -y postgresql postgresql-contrib
sudo apt-get install -y nginx

# 2. Database Setup
DB_NAME="gbot_db"
DB_USER="gbot_user"
DB_PASS="$(openssl rand -hex 12)"

echo "Checking for existing PostgreSQL database and user..."

# Check if the database already exists
if sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
    echo "Database '$DB_NAME' already exists. Skipping creation."
else
    echo "Creating database '$DB_NAME'..."
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME;"
fi

# Check if the user already exists
if sudo -u postgres psql -t -c "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1; then
    echo "User '$DB_USER' already exists. Skipping creation."
else
    echo "Creating user '$DB_USER'..."
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
fi
sudo -u postgres psql -c "ALTER ROLE $DB_USER SET client_encoding TO 'utf8';"
sudo -u postgres psql -c "ALTER ROLE $DB_USER SET default_transaction_isolation TO 'read committed';"
sudo -u postgres psql -c "ALTER ROLE $DB_USER SET timezone TO 'UTC';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"

# 3. Application Setup
APP_DIR="/var/www/gbot_webapp"

echo "Setting up application directory..."
sudo mkdir -p $APP_DIR
sudo chown -R $USER:$USER $APP_DIR

# Create virtual environment
python3 -m venv $APP_DIR/venv
source $APP_DIR/venv/bin/activate

# Copy application files
rsync -a . $APP_DIR/

# Install Python dependencies
pip install -r $APP_DIR/requirements.txt

# 4. Environment Configuration
SECRET_KEY="$(openssl rand -hex 24)"
WHITELIST_TOKEN="$(openssl rand -hex 16)"
DATABASE_URL="postgresql://$DB_USER:$DB_PASS@localhost/$DB_NAME"

echo "Creating .env file..."
cat << EOF > $APP_DIR/.env
SECRET_KEY=$SECRET_KEY
WHITELIST_TOKEN=$WHITELIST_TOKEN
DATABASE_URL=$DATABASE_URL
EOF

# 5. Gunicorn Service
echo "Configuring Gunicorn systemd service..."

cat << EOF | sudo tee /etc/systemd/system/gbot.service
[Unit]
Description=Gunicorn instance to serve gbot_webapp
After=network.target

[Service]
User=$USER
Group=www-data
WorkingDirectory=$APP_DIR
Environment="PATH=$APP_DIR/venv/bin"
ExecStart=$APP_DIR/venv/bin/gunicorn --workers 3 --bind unix:gbot.sock -m 007 wsgi:app

[Install]
WantedBy=multi-user.target
EOF

# Create wsgi.py for Gunicorn
cat << EOF > $APP_DIR/wsgi.py
from app import app

if __name__ == "__main__":
    app.run()
EOF

# 6. Nginx Reverse Proxy
echo "Configuring Nginx reverse proxy..."

cat << EOF | sudo tee /etc/nginx/sites-available/gbot
server {
    listen 80;
    server_name your_domain_or_ip;

    location / {
        include proxy_params;
        proxy_pass http://unix:$APP_DIR/gbot.sock;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/gbot /etc/nginx/sites-enabled
sudo nginx -t

# 7. Start Services
echo "Starting and enabling services..."
sudo systemctl daemon-reload
sudo systemctl start gbot
sudo systemctl enable gbot
sudo systemctl restart nginx

echo "--------------------------------------------------"
echo "Installation Complete!"
echo ""
echo "Database Name: $DB_NAME"
echo "Database User: $DB_USER"
echo "Database Password: $DB_PASS"
echo ""
echo "Your application is running at http://your_domain_or_ip"
echo "Remember to replace 'your_domain_or_ip' in /etc/nginx/sites-available/gbot"
echo "--------------------------------------------------"
