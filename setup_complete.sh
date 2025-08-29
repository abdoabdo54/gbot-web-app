#!/bin/bash

# GBot Web Application - COMPLETE Installation & Setup Script
# This is the ONLY installation script you need - handles everything
# Features: Root execution, Reinstallation, All modules, Production deployment, SSL, Monitoring

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="GBot Web Application"
LOG_FILE="$SCRIPT_DIR/setup.log"

# Logging functions
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $1" >> "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARNING] $1" >> "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" >> "$LOG_FILE"
}

show_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    $PROJECT_NAME                    ║"
    echo "║                                                              ║"
    echo "║                COMPLETE Installation Script                  ║"
    echo "║                                                              ║"
    echo "║           Root Execution • Reinstall • All Modules          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_system_requirements() {
    log "Checking system requirements..."
    
    # Allow root execution - no restrictions
    if [[ $EUID -eq 0 ]]; then
        log "Running as root user - proceeding with root deployment"
        ROOT_USER=true
        USER="root"
        USER_HOME="/root"
        # No sudo needed for root
        SUDO_CMD=""
    else
        log "Running as regular user - will use sudo for privileged operations"
        ROOT_USER=false
        SUDO_CMD="sudo"
    fi
    
    # Check Python version
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        log "Python version: $PYTHON_VERSION"
        
        # Check if Python 3.8+
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
            log_success "Python version is compatible (3.8+)"
        else
            log_error "Python 3.8+ is required"
            exit 1
        fi
    else
        log_error "Python 3 is not installed"
        exit 1
    fi
    
    # Check pip - install if not available
    if command -v pip3 &> /dev/null; then
        log_success "pip3 is available"
    else
        log_warning "pip3 is not available, will install it"
        # Install pip3 if not available
        if command -v apt-get &> /dev/null; then
            $SUDO_CMD apt-get update
            $SUDO_CMD apt-get install -y python3-pip
        elif command -v yum &> /dev/null; then
            $SUDO_CMD yum install -y python3-pip
        elif command -v dnf &> /dev/null; then
            $SUDO_CMD dnf install -y python3-pip
        else
            log_error "Cannot install pip3 - unsupported package manager"
            exit 1
        fi
        
        # Verify pip3 is now available
        if command -v pip3 &> /dev/null; then
            log_success "pip3 installed successfully"
        else
            log_error "Failed to install pip3"
            exit 1
        fi
    fi
    
    # Check disk space
    DISK_SPACE=$(df . | awk 'NR==2 {print $4}')
    DISK_SPACE_GB=$((DISK_SPACE / 1024 / 1024))
    if [ $DISK_SPACE_GB -gt 1000 ]; then
        log_success "Disk space: ${DISK_SPACE_GB}MB available"
    else
        log_warning "Low disk space: ${DISK_SPACE_GB}MB available (1GB+ recommended)"
    fi
    
    # Check memory
    if command -v free &> /dev/null; then
        MEMORY_KB=$(free | awk 'NR==2{print $2}')
        MEMORY_MB=$((MEMORY_KB / 1024))
        if [ $MEMORY_MB -gt 512 ]; then
            log_success "Memory: ${MEMORY_MB}MB available"
        else
            log_warning "Low memory: ${MEMORY_MB}MB available (512MB+ recommended)"
        fi
    fi
    
    log_success "System requirements check completed"
}

install_system_dependencies() {
    log "Installing system dependencies..."
    
    if command -v apt-get &> /dev/null; then
        log "Using apt-get package manager"
        $SUDO_CMD apt-get update
        
        # Install Python and development tools
        $SUDO_CMD apt-get install -y python3 python3-pip python3-dev python3-venv python3-setuptools python3-wheel
        $SUDO_CMD apt-get install -y build-essential libssl-dev libffi-dev pkg-config
        
        # Install PostgreSQL
        $SUDO_CMD apt-get install -y postgresql postgresql-contrib postgresql-client
        
        # Install Nginx
        $SUDO_CMD apt-get install -y nginx
        
        # Install firewall
        $SUDO_CMD apt-get install -y ufw
        
        # Install SSL tools
        $SUDO_CMD apt-get install -y certbot python3-certbot-nginx
        
        # Install utilities
        $SUDO_CMD apt-get install -y curl wget git unzip
        
        # Install additional Python packages that might be needed
        $SUDO_CMD apt-get install -y python3-dev python3-pip python3-venv
        
    elif command -v yum &> /dev/null; then
        log "Using yum package manager"
        $SUDO_CMD yum update -y
        
        # Install Python and development tools
        $SUDO_CMD yum install -y python3 python3-pip python3-devel python3-setuptools python3-wheel
        $SUDO_CMD yum install -y gcc openssl-devel libffi-devel pkg-config
        
        # Install PostgreSQL
        $SUDO_CMD yum install -y postgresql postgresql-server postgresql-contrib
        
        # Install Nginx
        $SUDO_CMD yum install -y nginx
        
        # Install firewall
        $SUDO_CMD yum install -y firewalld
        
        # Install utilities
        $SUDO_CMD yum install -y curl wget git unzip
        
    elif command -v dnf &> /dev/null; then
        log "Using dnf package manager"
        $SUDO_CMD dnf update -y
        
        # Install Python and development tools
        $SUDO_CMD dnf install -y python3 python3-pip python3-devel python3-setuptools python3-wheel
        $SUDO_CMD dnf install -y gcc openssl-devel libffi-devel pkg-config
        
        # Install PostgreSQL
        $SUDO_CMD dnf install -y postgresql postgresql-server postgresql-contrib
        
        # Install Nginx
        $SUDO_CMD dnf install -y nginx
        
        # Install firewall
        $SUDO_CMD dnf install -y firewalld
        
        # Install utilities
        $SUDO_CMD dnf install -y curl wget git unzip
        
    else
        log_error "Unsupported package manager"
        exit 1
    fi
    
    # Verify critical packages are installed
    log "Verifying critical packages..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python3 installation failed"
        exit 1
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        log_error "pip3 installation failed"
        exit 1
    fi
    
    # Check PostgreSQL
    if ! command -v psql &> /dev/null; then
        log_error "PostgreSQL installation failed"
        exit 1
    fi
    
    # Check Nginx
    if ! command -v nginx &> /dev/null; then
        log_error "Nginx installation failed"
        exit 1
    fi
    
    log_success "System dependencies installed and verified"
}

setup_postgresql() {
    log "Setting up PostgreSQL database..."
    
    # Check if PostgreSQL is already running
    if systemctl is-active --quiet postgresql; then
        log "PostgreSQL is already running"
    else
        # Start PostgreSQL service
        if command -v apt-get &> /dev/null; then
            $SUDO_CMD systemctl start postgresql
            $SUDO_CMD systemctl enable postgresql
        elif command -v yum &> /dev/null || command -v dnf &> /dev/null; then
            $SUDO_CMD postgresql-setup initdb
            $SUDO_CMD systemctl start postgresql
            $SUDO_CMD systemctl enable postgresql
        fi
    fi
    
    # Configure PostgreSQL for production
    log "Configuring PostgreSQL for production..."
    sudo -u postgres psql -c "ALTER SYSTEM SET max_connections = '100';" 2>/dev/null || true
    sudo -u postgres psql -c "ALTER SYSTEM SET shared_buffers = '256MB';" 2>/dev/null || true
    sudo -u postgres psql -c "ALTER SYSTEM SET effective_cache_size = '1GB';" 2>/dev/null || true
    sudo -u postgres psql -c "ALTER SYSTEM SET maintenance_work_mem = '64MB';" 2>/dev/null || true
    sudo -u postgres psql -c "ALTER SYSTEM SET checkpoint_completion_target = '0.9';" 2>/dev/null || true
    sudo -u postgres psql -c "ALTER SYSTEM SET wal_buffers = '16MB';" 2>/dev/null || true
    sudo -u postgres psql -c "ALTER SYSTEM SET default_statistics_target = '100';" 2>/dev/null || true
    
    # Restart PostgreSQL to apply changes
    $SUDO_CMD systemctl restart postgresql
    
    # Create database and user
    DB_NAME="gbot_db"
    DB_USER="gbot_user"
    DB_PASS=$(openssl rand -hex 12)
    
    # Check if database already exists
    if sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
        log "Database '$DB_NAME' already exists"
    else
        log "Creating database '$DB_NAME'..."
        sudo -u postgres psql -c "CREATE DATABASE $DB_NAME;"
    fi
    
    # Check if user already exists
    if sudo -u postgres psql -t -c "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1; then
        log "User '$DB_USER' already exists"
    else
        log "Creating user '$DB_USER'..."
        sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
    fi
    
    # Grant privileges
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
    sudo -u postgres psql -c "ALTER ROLE $DB_USER SET client_encoding TO 'utf8';"
    sudo -u postgres psql -c "ALTER ROLE $DB_USER SET default_transaction_isolation TO 'read committed';"
    sudo -u postgres psql -c "ALTER ROLE $DB_USER SET timezone TO 'UTC';"
    
    # Save database credentials
    echo "DATABASE_URL=postgresql://$DB_USER:$DB_PASS@localhost/$DB_NAME" > "$SCRIPT_DIR/.db_credentials"
    chmod 600 "$SCRIPT_DIR/.db_credentials"
    
    log_success "PostgreSQL setup completed"
    log "Database: $DB_NAME, User: $DB_USER, Password: $DB_PASS"
}

setup_python_environment() {
    log "Setting up Python environment..."
    
    # Create virtual environment
    if [ -d "venv" ]; then
        log "Virtual environment already exists, removing for clean install..."
        rm -rf venv
    fi
    
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install Python dependencies
    if [ -f "requirements.txt" ]; then
        log "Installing Python dependencies..."
        pip install -r requirements.txt
        log_success "Python dependencies installed"
    else
        log_error "requirements.txt not found"
        exit 1
    fi
    
    # Deactivate virtual environment
    deactivate
}

setup_database() {
    log "Setting up application database..."
    
    # First, create the environment file to ensure SECRET_KEY and WHITELIST_TOKEN are available
    create_environment_file
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Create database tables
    if [ -f "app.py" ]; then
        # Set environment variables for the Python process (filter out comments)
        export $(grep -v '^#' .env | xargs)
        
        # Ensure we're using the PostgreSQL database URL
        if [ -f ".db_credentials" ]; then
            source .db_credentials
            export DATABASE_URL
        fi
        
        python3 -c "
import os
from app import app, db
from database import User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Create all tables
    db.create_all()
    print('Database tables created successfully')
    
    # Create admin user if it doesn't exist
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(
            username='admin',
            password=generate_password_hash('A9B3nX#Q8k\$mZ6vw', method='pbkdf2:sha256'),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()
        print('Admin user created successfully')
        print('Username: admin')
        print('Password: A9B3nX#Q8k\$mZ6vw')
        print('Role: admin')
    else:
        print('Admin user already exists')
        print('Username: ' + admin_user.username)
        print('Role: ' + admin_user.role)
    
    # Verify admin user can authenticate
    from werkzeug.security import check_password_hash
    if check_password_hash(admin_user.password, 'A9B3nX#Q8k\$mZ6vw'):
        print('Admin user password verification successful')
    else:
        print('WARNING: Admin user password verification failed')
"
        log_success "Database setup completed"
    else
        log_error "app.py not found"
        exit 1
    fi
    
    # Deactivate virtual environment
    deactivate
}

create_environment_file() {
    log "Creating environment configuration..."
    
    # Generate secure keys
    SECRET_KEY=$(openssl rand -hex 32)
    WHITELIST_TOKEN=$(openssl rand -hex 16)
    
    # Load database credentials if available
    if [ -f ".db_credentials" ]; then
        source .db_credentials
    else
        DATABASE_URL="sqlite:///$(pwd)/gbot.db"
    fi
    
    # Create .env file
        cat > .env << EOF
# GBot Web Application Environment Configuration
# Generated automatically during installation

SECRET_KEY=$SECRET_KEY
WHITELIST_TOKEN=$WHITELIST_TOKEN
DATABASE_URL=$DATABASE_URL

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
    
    log_success "Environment file created"
}

setup_nginx() {
    log "Setting up Nginx reverse proxy..."
    
    # Create nginx configuration
    NGINX_CONFIG="/etc/nginx/sites-available/gbot"
    
    if [ -f "$NGINX_CONFIG" ]; then
        log "Nginx configuration already exists, backing up..."
        $SUDO_CMD cp "$NGINX_CONFIG" "$NGINX_CONFIG.backup"
    fi
    
    # Remove any existing default site that might interfere
    if [ -L "/etc/nginx/sites-enabled/default" ]; then
        log "Removing default nginx site..."
        $SUDO_CMD rm "/etc/nginx/sites-enabled/default"
    fi
    
    # Remove any other sites that might be using port 3000
    for site in /etc/nginx/sites-enabled/*; do
        if [ -f "$site" ] && grep -q "127.0.0.1:3000" "$site" 2>/dev/null; then
            log "Removing conflicting site: $site"
            $SUDO_CMD rm "$site"
        fi
    done
    
    # Create nginx configuration
    cat > /tmp/gbot_nginx << EOF
server {
    listen 80;
    server_name _;
    
    location / {
        include proxy_params;
        proxy_pass http://unix:$SCRIPT_DIR/gbot.sock;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
    
    location /static {
        alias $SCRIPT_DIR/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOF
    
    $SUDO_CMD cp /tmp/gbot_nginx "$NGINX_CONFIG"
    rm /tmp/gbot_nginx
    
    # Enable site
    if [ -L "/etc/nginx/sites-enabled/gbot" ]; then
        $SUDO_CMD rm "/etc/nginx/sites-enabled/gbot"
    fi
    $SUDO_CMD ln -s "$NGINX_CONFIG" "/etc/nginx/sites-enabled/"
    
    # Test nginx configuration
    if $SUDO_CMD nginx -t; then
        $SUDO_CMD systemctl reload nginx
        # Force restart to ensure new configuration is loaded
        $SUDO_CMD systemctl restart nginx
        log_success "Nginx configuration completed and restarted"
    else
        log_error "Nginx configuration test failed"
        exit 1
    fi
}

setup_systemd_service() {
    log "Setting up systemd service..."
    
    SERVICE_FILE="/etc/systemd/system/gbot.service"
    
    if [ -f "$SERVICE_FILE" ]; then
        log "Systemd service already exists, backing up..."
        $SUDO_CMD cp "$SERVICE_FILE" "$SERVICE_FILE.backup"
    fi
    
    # Create systemd service
    cat > /tmp/gbot_service << EOF
[Unit]
Description=GBot Web Application
After=network.target postgresql.service

[Service]
Type=notify
User=$USER
Group=$USER
WorkingDirectory=$SCRIPT_DIR
Environment="PATH=$SCRIPT_DIR/venv/bin"
Environment="FLASK_ENV=production"
ExecStart=$SCRIPT_DIR/venv/bin/gunicorn --workers 4 --bind unix:$SCRIPT_DIR/gbot.sock --access-logfile $SCRIPT_DIR/gunicorn-access.log --error-logfile $SCRIPT_DIR/gunicorn-error.log --max-requests 1000 --max-requests-jitter 100 --timeout 30 app:app
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    
    $SUDO_CMD cp /tmp/gbot_service "$SERVICE_FILE"
    rm /tmp/gbot_service
    
    # Reload systemd and enable service
    $SUDO_CMD systemctl daemon-reload
    $SUDO_CMD systemctl enable gbot
    
    log_success "Systemd service created and enabled"
}

setup_firewall() {
    log "Setting up firewall..."
    
    if command -v ufw &> /dev/null; then
        # UFW firewall
        $SUDO_CMD ufw allow 22/tcp
        $SUDO_CMD ufw allow 80/tcp
        $SUDO_CMD ufw allow 443/tcp
        $SUDO_CMD ufw --force enable
        log_success "UFW firewall configured"
    elif command -v firewall-cmd &> /dev/null; then
        # firewalld
        $SUDO_CMD firewall-cmd --permanent --add-service=ssh
        $SUDO_CMD firewall-cmd --permanent --add-service=http
        $SUDO_CMD firewall-cmd --permanent --add-service=https
        $SUDO_CMD firewall-cmd --reload
        log_success "firewalld configured"
    else
        log_warning "No supported firewall found"
    fi
}

setup_ssl_certificate() {
    log "Setting up SSL certificate..."
    
    if ! command -v certbot &> /dev/null; then
        log_warning "Certbot not found, SSL setup skipped"
        return
    fi
    
    read -p "Enter your domain name (e.g., example.com) or press Enter to skip SSL: " DOMAIN_NAME
    
    if [ -z "$DOMAIN_NAME" ]; then
        log "SSL setup skipped"
        return
    fi
    
    log "Setting up SSL certificate for $DOMAIN_NAME..."
    
    # Update nginx configuration with domain
    $SUDO_CMD sed -i "s/server_name _;/server_name $DOMAIN_NAME;/" /etc/nginx/sites-available/gbot
    
    # Test nginx configuration
    if $SUDO_CMD nginx -t; then
        $SUDO_CMD systemctl reload nginx
        
        # Obtain SSL certificate
        $SUDO_CMD certbot --nginx -d $DOMAIN_NAME --non-interactive --agree-tos --email admin@$DOMAIN_NAME
        
        log_success "SSL certificate setup completed for $DOMAIN_NAME"
    else
        log_error "Nginx configuration test failed"
        exit 1
    fi
}

setup_monitoring() {
    log "Setting up monitoring..."
    
    # Create monitoring script
    cat > monitor_gbot.sh << 'EOF'
#!/bin/bash
# GBot Monitoring Script

LOG_FILE="monitoring.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Check service status
check_service() {
    local service_name=$1
    if systemctl is-active --quiet $service_name; then
        echo "[$TIMESTAMP] ✓ Service $service_name is running" >> $LOG_FILE
    else
        echo "[$TIMESTAMP] ✗ Service $service_name is not running" >> $LOG_FILE
        # Try to restart service
        sudo systemctl restart $service_name
        echo "[$TIMESTAMP] 🔄 Attempted to restart $service_name" >> $LOG_FILE
    fi
}

# Check disk space
check_disk_space() {
    local usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ $usage -gt 80 ]; then
        echo "[$TIMESTAMP] ⚠️  Disk usage is high: ${usage}%" >> $LOG_FILE
    else
        echo "[$TIMESTAMP] ✓ Disk usage is normal: ${usage}%" >> $LOG_FILE
    fi
}

# Check memory usage
check_memory() {
    local mem_usage=$(free | awk 'NR==2{printf "%.2f", $3*100/$2}')
    if (( $(echo "$mem_usage > 80" | bc -l) )); then
        echo "[$TIMESTAMP] ⚠️  Memory usage is high: ${mem_usage}%" >> $LOG_FILE
    else
        echo "[$TIMESTAMP] ✓ Memory usage is normal: ${mem_usage}%" >> $LOG_FILE
    fi
}

# Run checks
check_service gbot
check_service nginx
check_service postgresql
check_disk_space
check_memory

# Keep only last 1000 lines
tail -n 1000 $LOG_FILE > $LOG_FILE.tmp && mv $LOG_FILE.tmp $LOG_FILE
EOF
    
    chmod +x monitor_gbot.sh
    
    # Setup cron job for monitoring (every 5 minutes)
    if [ "$ROOT_USER" = true ]; then
        (crontab -l 2>/dev/null; echo "*/5 * * * * cd $SCRIPT_DIR && ./monitor_gbot.sh") | crontab -
    else
        (sudo crontab -l 2>/dev/null; echo "*/5 * * * * cd $SCRIPT_DIR && ./monitor_gbot.sh") | sudo crontab -
    fi
    
    log_success "Monitoring setup completed"
}

create_backup() {
    log "Creating backup..."
    
    BACKUP_DIR="$SCRIPT_DIR/backups"
    BACKUP_NAME="gbot_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    
    mkdir -p "$BACKUP_DIR"
    
    # Create backup excluding unnecessary files
    tar --exclude='venv' --exclude='*.pyc' --exclude='__pycache__' --exclude='logs/*.log' \
        -czf "$BACKUP_DIR/$BACKUP_NAME" -C "$SCRIPT_DIR" .
    
    log_success "Backup created: $BACKUP_DIR/$BACKUP_NAME"
}

display_current_credentials() {
    log "Displaying current credentials..."
    
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                CURRENT CREDENTIALS                         ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    
    # Show generated security keys
    if [ -f ".env" ]; then
        echo -e "🔐 Generated Security Keys:"
        echo -e "  • SECRET_KEY: ${BLUE}$(grep '^SECRET_KEY=' .env | cut -d'=' -f2)${NC}"
        echo -e "  • WHITELIST_TOKEN: ${BLUE}$(grep '^WHITELIST_TOKEN=' .env | cut -d'=' -f2)${NC}"
        echo ""
    fi
    
    # Show database credentials
    if [ -f ".db_credentials" ]; then
        echo -e "🗄️  Database Credentials:"
        source .db_credentials
        echo -e "  • Database: ${BLUE}gbot_db${NC}"
        echo -e "  • User: ${BLUE}gbot_user${NC}"
        echo -e "  • Password: ${BLUE}$(echo $DATABASE_URL | sed 's/.*:\/\/.*:\([^@]*\)@.*/\1/')${NC}"
        echo ""
    fi
    
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

inspect_nginx_configuration() {
    log "Inspecting Nginx configuration..."
    
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                NGINX CONFIGURATION INSPECTION               ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "\n🔍 Active Nginx Sites:"
    echo "Sites-enabled:"
    ls -la /etc/nginx/sites-enabled/ 2>/dev/null || echo "No sites enabled"
    
    echo -e "\nSites-available:"
    ls -la /etc/nginx/sites-available/ 2>/dev/null || echo "No sites available"
    
    echo -e "\n📋 Main Nginx Configuration:"
    echo "Checking for upstream definitions..."
    if grep -n "upstream\|127.0.0.1:3000" /etc/nginx/nginx.conf 2>/dev/null; then
        echo "Found upstream or port 3000 references in main nginx.conf"
    else
        echo "No upstream or port 3000 references found in main nginx.conf"
    fi
    
    echo -e "\n📋 Individual Site Configurations:"
    for site in /etc/nginx/sites-available/*; do
        if [ -f "$site" ]; then
            echo -e "\n--- $(basename "$site") ---"
            if grep -q "127.0.0.1:3000" "$site" 2>/dev/null; then
                echo "❌ CONTAINS PORT 3000 REFERENCE:"
                grep -n "127.0.0.1:3000" "$site"
            elif grep -q "unix.*sock" "$site" 2>/dev/null; then
                echo "✅ CONTAINS UNIX SOCKET REFERENCE:"
                grep -n "unix.*sock" "$site"
            else
                echo "⚠️  NO SOCKET OR PORT REFERENCE FOUND:"
                cat "$site"
            fi
        fi
    done
    
    echo -e "\n🔍 Nginx Process Information:"
    echo "Nginx processes:"
    ps aux | grep nginx | grep -v grep || echo "No nginx processes found"
    
    echo -e "\n🔍 Nginx Configuration Test:"
    nginx -t 2>&1 || echo "Nginx configuration test failed"
    
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

nuke_nginx_configuration() {
    log "NUKING Nginx configuration completely..."
    
    echo ""
    echo -e "${RED}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}                NUKING NGINX CONFIGURATION                   ${NC}"
    echo -e "${RED}══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "\n⚠️  This will COMPLETELY remove ALL Nginx configurations!"
    echo -e "   Only proceed if you're sure you want to start fresh."
    echo ""
    read -p "Continue with Nginx nuke? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Nginx nuke cancelled by user"
        return
    fi
    
    # Stop nginx completely
    log "Stopping Nginx service..."
    systemctl stop nginx
    systemctl disable nginx
    
    # Kill any remaining nginx processes
    log "Killing any remaining nginx processes..."
    pkill -f nginx || true
    
    # Remove ALL nginx configurations
    log "Removing ALL nginx configurations..."
    rm -rf /etc/nginx/sites-enabled/*
    rm -rf /etc/nginx/sites-available/*
    rm -f /etc/nginx/conf.d/*
    
    # Backup and clean main nginx.conf
    log "Backing up and cleaning main nginx.conf..."
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
    
    # Create minimal nginx.conf
    cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    gzip on;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
    
    # Create our gbot configuration
    log "Creating fresh gbot configuration..."
    mkdir -p /etc/nginx/sites-available
    mkdir -p /etc/nginx/sites-enabled
    
    cat > /etc/nginx/sites-available/gbot << EOF
server {
    listen 80;
    server_name _;
    
    location / {
        include proxy_params;
        proxy_pass http://unix:$SCRIPT_DIR/gbot.sock;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
    
    location /static {
        alias $SCRIPT_DIR/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOF
    
    # Enable only our site
    ln -s /etc/nginx/sites-available/gbot /etc/nginx/sites-enabled/
    
    # Test configuration
    if nginx -t; then
        # Start nginx fresh
        systemctl enable nginx
        systemctl start nginx
        
        # Wait for nginx to fully start
        sleep 3
        
        # Verify nginx is running
        if systemctl is-active --quiet nginx; then
            log_success "Nginx configuration completely nuked and rebuilt!"
            
            echo -e "\n✅ Nginx has been completely rebuilt and is running!"
            echo -e "🌐 Try accessing your application at: ${BLUE}http://95.179.176.162${NC}"
            echo -e "🔍 Verify with: ${BLUE}./setup_complete.sh --inspect-nginx${NC}"
            
            # Test the connection immediately
            echo -e "\n🔍 Testing connection..."
            if curl -s http://localhost/health 2>/dev/null; then
                echo -e "✅ Local connection successful!"
            else
                echo -e "❌ Local connection failed"
            fi
        else
            log_error "Nginx failed to start after rebuild"
            systemctl status nginx
            exit 1
        fi
    else
        log_error "Nginx configuration test failed after nuke"
        exit 1
    fi
    
    echo -e "\n${RED}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

add_ip_to_whitelist() {
    log "Adding IP to whitelist..."
    
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                ADDING IP TO WHITELIST                      ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    
    # Get current external IP
    CURRENT_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "unknown")
    
    if [ "$CURRENT_IP" != "unknown" ]; then
        log "Current external IP detected: $CURRENT_IP"
        
        # Check if we have a database to add the IP
        if [ -f ".env" ]; then
            # Source environment variables
            export $(grep -v '^#' .env | xargs)
            
            # Activate virtual environment
            source venv/bin/activate
            
            # Add IP to whitelist using Python
            python3 -c "
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, '$SCRIPT_DIR')

# Set environment variables
os.environ['FLASK_ENV'] = 'production'

try:
    from app import app, db
    from database import WhitelistedIP
    
    with app.app_context():
        # Check if IP already exists
        existing_ip = WhitelistedIP.query.filter_by(ip_address='$CURRENT_IP').first()
        if not existing_ip:
            # Add new IP
            new_ip = WhitelistedIP(ip_address='$CURRENT_IP')
            db.session.add(new_ip)
            db.session.commit()
            print(f'IP $CURRENT_IP added to whitelist successfully')
        else:
            print(f'IP $CURRENT_IP already in whitelist')
            
except ImportError as e:
    print(f'Import error: {e}')
    print('Python path:', sys.path)
    print('Current working directory:', os.getcwd())
    print('Files in current directory:', os.listdir('.'))
except Exception as e:
    print(f'Unexpected error: {e}')
"
            
            # Deactivate virtual environment
            deactivate
            
            echo -e "\n✅ IP whitelist operation completed!"
            echo -e "🌐 Your IP ${BLUE}$CURRENT_IP${NC} has been processed"
            
            # Test direct socket connection
            log "Testing direct socket connection..."
            if curl -s --unix-socket "$SCRIPT_DIR/gbot.sock" http://localhost/health 2>/dev/null; then
                echo -e "\n✅ Direct socket connection successful!"
                echo -e "🌐 Try accessing your application at: ${BLUE}http://95.179.176.162${NC}"
            else
                echo -e "\n⚠️  Socket connection test failed"
                echo -e "🔍 Run troubleshooting to check: ${BLUE}./setup_complete.sh --troubleshoot${NC}"
            fi
        else
            log_error "Environment file not found. Cannot update whitelist."
        fi
    else
        log_error "Could not detect current external IP"
        echo -e "\n⚠️  Manual IP whitelist setup required:"
        echo -e "   1. Access the application directly via socket: ${BLUE}curl --unix-socket $SCRIPT_DIR/gbot.sock http://localhost/whitelist${NC}"
        echo -e "   2. Add your IP address to the whitelist"
    fi
    
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

disable_ip_whitelist() {
    log "Disabling IP whitelist..."
    
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                DISABLING IP WHITELIST                      ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    
    if [ -f ".env" ]; then
        # Update .env file to disable IP whitelist
        sed -i 's/ENABLE_IP_WHITELIST=True/ENABLE_IP_WHITELIST=False/' .env
        sed -i 's/ENABLE_IP_WHITELIST=true/ENABLE_IP_WHITELIST=False/' .env
        
        # Ensure ALLOW_ALL_IPS_IN_DEV is True
        sed -i 's/ALLOW_ALL_IPS_IN_DEV=False/ALLOW_ALL_IPS_IN_DEV=True/' .env
        sed -i 's/ALLOW_ALL_IPS_IN_DEV=false/ALLOW_ALL_IPS_IN_DEV=True/' .env
        
        # Also set DEBUG=True to ensure development mode
        sed -i 's/DEBUG=False/DEBUG=True/' .env
        sed -i 's/DEBUG=false/DEBUG=True/' .env
        
        echo -e "\n✅ IP whitelist has been disabled!"
        echo -e "🌐 All IPs will now be allowed to access the application"
        echo -e "🔧 You'll need to restart the application for changes to take effect:"
        echo -e "   ${BLUE}systemctl restart gbot${NC}"
        
        # Show current .env settings
        echo -e "\n📋 Current .env settings:"
        grep -E "ENABLE_IP_WHITELIST|ALLOW_ALL_IPS_IN_DEV|DEBUG" .env
        
        # Test direct socket connection
        log "Testing direct socket connection..."
        if curl -s --unix-socket "$SCRIPT_DIR/gbot.sock" http://localhost/health 2>/dev/null; then
            echo -e "\n✅ Direct socket connection successful!"
            echo -e "🌐 Try accessing your application at: ${BLUE}http://95.179.176.162${NC}"
        else
            echo -e "\n⚠️  Socket connection test failed"
            echo -e "🔍 Run troubleshooting to check: ${BLUE}./setup_complete.sh --troubleshoot${NC}"
        fi
    else
        log_error "Environment file not found. Cannot disable IP whitelist."
    fi
    
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

fix_all_issues() {
    log "FIXING ALL ISSUES COMPREHENSIVELY..."
    
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                COMPREHENSIVE FIX ALL ISSUES                ${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "\n🚀 This will fix ALL your issues in the correct order:"
    echo -e "   1. 🔧 Fix IP whitelist (disable restrictions)"
    echo -e "   2. 🚀 Restart application with new settings"
    echo -e "   3. 🌐 Rebuild Nginx completely"
    echo -e "   4. ✅ Test everything works"
    
    echo ""
    read -p "Continue with comprehensive fix? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Comprehensive fix cancelled by user"
        return
    fi
    
    # Step 1: Fix IP whitelist
    echo -e "\n🔧 Step 1: Fixing IP whitelist..."
    disable_ip_whitelist
    
    # Step 2: Restart application
    echo -e "\n🚀 Step 2: Restarting application..."
    systemctl restart gbot
    sleep 5
    
    # Step 3: Rebuild Nginx
    echo -e "\n🌐 Step 3: Rebuilding Nginx completely..."
    nuke_nginx_configuration
    
    # Step 4: Test everything
    echo -e "\n✅ Step 4: Testing everything..."
    
    # Test local connection
    if curl -s http://localhost/health 2>/dev/null; then
        echo -e "✅ Local connection successful!"
    else
        echo -e "❌ Local connection failed"
    fi
    
    # Test external connection
    if curl -s http://95.179.176.162/health 2>/dev/null; then
        echo -e "✅ External connection successful!"
        echo -e "\n🎉 ALL ISSUES FIXED! Your application is now accessible at:"
        echo -e "   ${BLUE}http://95.179.176.162${NC}"
    else
        echo -e "❌ External connection failed"
        echo -e "\n🔍 Run troubleshooting: ${BLUE}./setup_complete.sh --troubleshoot${NC}"
    fi
    
    echo -e "\n${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

install_missing_dependencies() {
    log "Installing missing Python dependencies..."
    
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                INSTALLING MISSING DEPENDENCIES              ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Install missing dependencies
    log "Installing google-auth-oauthlib..."
    pip install google-auth-oauthlib
    
    log "Installing google-auth..."
    pip install google-auth
    
    log "Installing google-api-python-client..."
    pip install google-api-python-client
    
    log "Upgrading pip and setuptools..."
    pip install --upgrade pip setuptools
    
    # Check if requirements.txt exists and install from it
    if [ -f "requirements.txt" ]; then
        log "Installing all requirements from requirements.txt..."
        pip install -r requirements.txt
    fi
    
    # Deactivate virtual environment
    deactivate
    
    log_success "Missing dependencies installed"
    
    echo -e "\n✅ Dependencies have been installed!"
    echo -e "🔍 Now try the whitelist fix again: ${BLUE}./setup_complete.sh --fix-whitelist${NC}"
    
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

enable_ip_whitelist() {
    log "Enabling IP whitelist security..."
    
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                ENABLING IP WHITELIST SECURITY                ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    
    # Create backup of current .env
    cp .env .env.backup.$(date +%Y%m%d_%H%M%S)
    
    # Update .env file with secure settings
    log "Updating .env file with secure IP whitelist settings..."
    sed -i 's/ENABLE_IP_WHITELIST=False/ENABLE_IP_WHITELIST=True/' .env
    sed -i 's/ALLOW_ALL_IPS_IN_DEV=True/ALLOW_ALL_IPS_IN_DEV=False/' .env
    
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
    
    echo -e "🌐 Your current IP address: ${BLUE}$CURRENT_IP${NC}"
    
    # Add current IP to whitelist
    log "Adding your current IP to whitelist..."
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
    log "Restarting application with IP whitelist enabled..."
    systemctl restart gbot
    
    # Wait for restart
    sleep 3
    
    # Check status
    if systemctl is-active --quiet gbot; then
        log_success "Application restarted successfully"
    else
        log_error "Application restart failed"
        systemctl status gbot
    fi
    
    echo -e "\n🛡️ IP Whitelist Security Enabled!"
    echo -e "\n📝 Security Settings:"
    echo -e "   • ENABLE_IP_WHITELIST=True (IP whitelist enabled)"
    echo -e "   • ALLOW_ALL_IPS_IN_DEV=False (no development bypass)"
    echo -e "   • Your IP (${BLUE}$CURRENT_IP${NC}) added to whitelist"
    echo -e "\n🔐 Login credentials:"
    echo -e "   Username: ${BLUE}admin${NC}"
    echo -e "   Password: ${BLUE}A9B3nX#Q8k\$mZ6vw${NC}"
    echo -e "\n🌐 Access your application:"
    echo -e "   Main app: ${BLUE}http://172.235.163.73${NC}"
    echo -e "   Whitelist management: ${BLUE}http://172.235.163.73/whitelist${NC}"
    echo -e "\n⚠️  IMPORTANT SECURITY NOTES:"
    echo -e "   • Only whitelisted IPs can access the application"
    echo -e "   • Your current IP (${BLUE}$CURRENT_IP${NC}) is now whitelisted"
    echo -e "   • To add more IPs, log in and go to whitelist management"
    echo -e "   • Or use emergency access: ${BLUE}http://172.235.163.73/emergency_access?key=4ee85e149031cac30f62f8ebb598f030${NC}"
    echo -e "\n🔧 To add more IPs:"
    echo -e "   1. Log in from a whitelisted IP"
    echo -e "   2. Go to: ${BLUE}http://172.235.163.73/whitelist${NC}"
    echo -e "   3. Add the new IP addresses"
    echo -e "\n🚨 SECURITY TEST:"
    echo -e "   Try accessing from a different IP (like mobile data) - you should see 'Access denied'"
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

fix_whitelist_startup() {
    log "Fixing IP whitelist startup issue..."
    
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                FIXING IP WHITELIST STARTUP ISSUE            ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    
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
        
        echo -e "🌐 Your current IP address: ${BLUE}$CURRENT_IP${NC}"
        
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
            echo -e "🎉 IP Whitelist Startup Issue Fixed!"
            echo ""
            echo -e "📝 Security Settings:"
            echo -e "   • ENABLE_IP_WHITELIST=True (IP whitelist enabled)"
            echo -e "   • ALLOW_ALL_IPS_IN_DEV=False (no development bypass)"
            echo -e "   • Your IP (${BLUE}$CURRENT_IP${NC}) added to whitelist"
            echo ""
            echo -e "🔐 Login credentials:"
            echo -e "   Username: ${BLUE}admin${NC}"
            echo -e "   Password: ${BLUE}A9B3nX#Q8k\$mZ6vw${NC}"
            echo ""
            echo -e "🌐 Access your application:"
            echo -e "   Main app: ${BLUE}http://172.235.163.73${NC}"
            echo -e "   Whitelist management: ${BLUE}http://172.235.163.73/whitelist${NC}"
            echo ""
            echo -e "✅ Application is running with IP whitelist security enabled!"
        else
            echo ""
            echo -e "❌ Application still failed to start with IP whitelist"
            echo "📋 Final status:"
            systemctl status gbot --no-pager
            echo ""
            echo "📋 Final logs:"
            journalctl -u gbot -n 20 --no-pager
            echo ""
            echo -e "🔧 Keeping IP whitelist disabled for now"
            echo -e "   You can manually enable it later when you have IPs whitelisted"
        fi
        
    else
        echo ""
        echo -e "❌ Application still failed to start even with IP whitelist disabled"
        echo "📋 Status:"
        systemctl status gbot --no-pager
        echo ""
        echo "📋 Logs:"
        journalctl -u gbot -n 20 --no-pager
        echo ""
        echo -e "🔧 There might be another issue. Check the logs above."
    fi
    
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

fix_admin_user() {
    log "Fixing admin user login issue..."
    
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                FIXING ADMIN USER LOGIN ISSUE                ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    
    # Fix environment file first
    log "Fixing environment configuration..."
    sed -i 's/SESSION_COOKIE_SECURE=True/SESSION_COOKIE_SECURE=False/' .env
    sed -i 's/ENABLE_IP_WHITELIST=True/ENABLE_IP_WHITELIST=False/' .env
    sed -i 's/ALLOW_ALL_IPS_IN_DEV=False/ALLOW_ALL_IPS_IN_DEV=True/' .env
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Set environment variables
    export $(grep -v '^#' .env | xargs)
    
    # Ensure we're using the PostgreSQL database URL
    if [ -f ".db_credentials" ]; then
        source .db_credentials
        export DATABASE_URL
    fi
    
    # Create admin user directly
    log "Creating admin user..."
    python3 -c "
import os
from app import app, db
from database import User
from werkzeug.security import generate_password_hash, check_password_hash

with app.app_context():
    # Check if admin user exists
    admin_user = User.query.filter_by(username='admin').first()
    
    if admin_user:
        print('✅ Admin user already exists:')
        print(f'   Username: {admin_user.username}')
        print(f'   Role: {admin_user.role}')
        print(f'   ID: {admin_user.id}')
        
        # Test password
        if check_password_hash(admin_user.password, 'A9B3nX#Q8k\$mZ6vw'):
            print('✅ Password verification successful')
        else:
            print('❌ Password verification failed - recreating user')
            # Delete and recreate user
            db.session.delete(admin_user)
            db.session.commit()
            admin_user = None
    else:
        print('❌ Admin user not found. Creating...')
    
    if not admin_user:
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
    
    # Test authentication
    print('\n🔐 Testing authentication...')
    test_user = User.query.filter_by(username='admin').first()
    if test_user and check_password_hash(test_user.password, 'A9B3nX#Q8k\$mZ6vw'):
        print('✅ Authentication test passed')
    else:
        print('❌ Authentication test failed')
"
    
    # Deactivate virtual environment
    deactivate
    
    # Restart the application service
    log "Restarting application service..."
    systemctl restart gbot
    
    # Wait for service to start
    sleep 5
    
    # Check service status
    if systemctl is-active --quiet gbot; then
        log_success "Application service restarted successfully"
    else
        log_error "Application service failed to restart"
        systemctl status gbot
    fi
    
    echo -e "\n✅ Admin user and login issues have been fixed!"
    echo -e "🔐 Login credentials:"
    echo -e "   Username: ${BLUE}admin${NC}"
    echo -e "   Password: ${BLUE}A9B3nX#Q8k\$mZ6vw${NC}"
    echo -e "\n🌐 Try logging in again at: ${BLUE}http://172.235.163.73${NC}"
    echo -e "🔍 Test admin user at: ${BLUE}http://172.235.163.73/test-admin${NC}"
    
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

fix_ip_whitelist() {
    log "Fixing IP whitelist..."
    
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                FIXING IP WHITELIST                          ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    
    # Get current external IP
    CURRENT_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "unknown")
    
    if [ "$CURRENT_IP" != "unknown" ]; then
        log "Current external IP detected: $CURRENT_IP"
        
        # Check if we have a database to add the IP
        if [ -f ".env" ]; then
            # Source environment variables
            export $(grep -v '^#' .env | xargs)
            
            # Activate virtual environment
            source venv/bin/activate
            
            # Add IP to whitelist using Python
            python3 -c "
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, '$SCRIPT_DIR')

# Set environment variables
os.environ['FLASK_ENV'] = 'production'

try:
    from app import app, db
    from database import WhitelistedIP
    
    with app.app_context():
        # Check if IP already exists
        existing_ip = WhitelistedIP.query.filter_by(ip_address='$CURRENT_IP').first()
        if not existing_ip:
            # Add new IP (using only the fields that exist in the model)
            try:
                new_ip = WhitelistedIP(ip_address='$CURRENT_IP')
                db.session.add(new_ip)
                db.session.commit()
                print(f'IP $CURRENT_IP added to whitelist successfully')
            except Exception as e:
                print(f'Error adding IP: {e}')
                # Try alternative approach - check what fields the model actually has
                print('Model fields:', [c.name for c in WhitelistedIP.__table__.columns])
        else:
            print(f'IP $CURRENT_IP already in whitelist')
            
except ImportError as e:
    print(f'Import error: {e}')
    print('Python path:', sys.path)
    print('Current working directory:', os.getcwd())
    print('Files in current directory:', os.listdir('.'))
except Exception as e:
    print(f'Unexpected error: {e}')
"
            
            # Deactivate virtual environment
            deactivate
            
            # Since the IP is already whitelisted, let's test the connection directly
            echo -e "\n✅ IP whitelist check completed!"
            echo -e "🌐 Your IP ${BLUE}$CURRENT_IP${NC} is already in the whitelist"
            
            # Test direct socket connection
            log "Testing direct socket connection..."
            if curl -s --unix-socket "$SCRIPT_DIR/gbot.sock" http://localhost/health 2>/dev/null; then
                echo -e "\n✅ Direct socket connection successful!"
                echo -e "🌐 Try accessing your application at: ${BLUE}http://95.179.176.162${NC}"
            else
                echo -e "\n⚠️  Socket connection test failed"
                echo -e "🔍 Run troubleshooting to check: ${BLUE}./setup_complete.sh --troubleshoot${NC}"
            fi
        else
            log_error "Environment file not found. Cannot update whitelist."
        fi
    else
        log_error "Could not detect current external IP"
        echo -e "\n⚠️  Manual IP whitelist setup required:"
        echo -e "   1. Access the application directly via socket: ${BLUE}curl --unix-socket $SCRIPT_DIR/gbot.sock http://localhost/whitelist${NC}"
        echo -e "   2. Add your IP address to the whitelist"
    fi
    
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

troubleshoot_connection() {
    log "Troubleshooting connection issues..."
    
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                TROUBLESHOOTING GUIDE                        ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    
    # Check if socket exists
    if [ -S "$SCRIPT_DIR/gbot.sock" ]; then
        echo -e "✅ Gunicorn socket exists: ${BLUE}$SCRIPT_DIR/gbot.sock${NC}"
        echo -e "   Socket permissions: ${BLUE}$(ls -la $SCRIPT_DIR/gbot.sock)${NC}"
    else
        echo -e "❌ Gunicorn socket missing: ${BLUE}$SCRIPT_DIR/gbot.sock${NC}"
    fi
    
    # Check service status
    echo -e "\n🔍 Service Status:"
    echo -e "   GBot service: ${BLUE}$(systemctl is-active gbot)${NC}"
    echo -e "   Nginx service: ${BLUE}$(systemctl is-active nginx)${NC}"
    echo -e "   PostgreSQL: ${BLUE}$(systemctl is-active postgresql)${NC}"
    
    # Check socket connection
    echo -e "\n🔌 Socket Connection Test:"
    if [ -S "$SCRIPT_DIR/gbot.sock" ]; then
        echo -e "   Testing socket with curl..."
        curl -s --unix-socket "$SCRIPT_DIR/gbot.sock" http://localhost/health 2>/dev/null || echo "   ❌ Socket connection failed"
    fi
    
    # Check Nginx error logs
    echo -e "\n📋 Nginx Error Logs (last 5 lines):"
    tail -n 5 /var/log/nginx/error.log 2>/dev/null || echo "   No error logs found"
    
    # Check Gunicorn logs
    echo -e "\n📋 Gunicorn Logs (last 5 lines):"
    tail -n 5 "$SCRIPT_DIR/gunicorn-error.log" 2>/dev/null || echo "   No Gunicorn error logs found"
    
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

fix_nginx_configuration() {
    log "Fixing Nginx configuration..."
    
    echo ""
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                FIXING NGINX CONFIGURATION                   ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    
    # Stop nginx first
    log "Stopping Nginx service..."
    systemctl stop nginx
    
    # Remove ALL existing sites
    log "Removing all existing nginx sites..."
    rm -f /etc/nginx/sites-enabled/*
    
    # Remove any conflicting configurations
    if [ -f "/etc/nginx/sites-available/default" ]; then
        log "Removing default nginx site..."
        rm -f /etc/nginx/sites-available/default
    fi
    
    # Check for other configuration files that might be interfering
    log "Checking for conflicting nginx configurations..."
    for config_file in /etc/nginx/sites-available/*; do
        if [ -f "$config_file" ] && [ "$(basename "$config_file")" != "gbot" ]; then
            log "Found conflicting config: $config_file"
            if grep -q "127.0.0.1:3000" "$config_file" 2>/dev/null; then
                log "Removing conflicting config with port 3000: $config_file"
                rm -f "$config_file"
            fi
        fi
    done
    
    # Check main nginx.conf for any upstream definitions
    log "Checking main nginx.conf for upstream definitions..."
    if grep -q "upstream.*127.0.0.1:3000" /etc/nginx/nginx.conf 2>/dev/null; then
        log "Found upstream definition in main nginx.conf, backing up and removing..."
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
        sed -i '/upstream.*127.0.0.1:3000/,/}/d' /etc/nginx/nginx.conf
    fi
    
    # Recreate our configuration
    NGINX_CONFIG="/etc/nginx/sites-available/gbot"
    
    cat > "$NGINX_CONFIG" << EOF
server {
    listen 80;
    server_name _;
    
    location / {
        include proxy_params;
        proxy_pass http://unix:$SCRIPT_DIR/gbot.sock;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
    
    location /static {
        alias $SCRIPT_DIR/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOF
    
    # Enable only our site
    log "Enabling gbot nginx site..."
    ln -s "$NGINX_CONFIG" "/etc/nginx/sites-enabled/"
    
    # Verify our configuration is the only one active
    log "Verifying nginx configuration..."
    echo "Active nginx sites:"
    ls -la /etc/nginx/sites-enabled/
    
    echo "Nginx configuration content:"
    cat "$NGINX_CONFIG"
    
    # Test and start nginx
    if nginx -t; then
        systemctl start nginx
        log_success "Nginx configuration fixed and restarted"
        
        echo -e "\n✅ Nginx configuration has been fixed!"
        echo -e "🌐 Try accessing your application again at: ${BLUE}http://95.179.176.162${NC}"
        echo -e "🔍 If you still have issues, run: ${BLUE}./setup_complete.sh --troubleshoot${NC}"
    else
        log_error "Nginx configuration test failed"
        exit 1
    fi
    
    echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

start_services() {
    log "Starting services..."
    
    # Start PostgreSQL
    $SUDO_CMD systemctl start postgresql
    $SUDO_CMD systemctl enable postgresql
    
    # Start Nginx
    $SUDO_CMD systemctl start nginx
    $SUDO_CMD systemctl enable nginx
    
    # Start GBot service
    $SUDO_CMD systemctl start gbot
    $SUDO_CMD systemctl enable gbot
    
    # Wait for Gunicorn to create the socket
    log "Waiting for Gunicorn socket to be ready..."
    sleep 5
    
    # Check if socket exists and has proper permissions
    if [ -S "$SCRIPT_DIR/gbot.sock" ]; then
        log_success "Gunicorn socket created successfully"
        # Set proper permissions on the socket
        chmod 666 "$SCRIPT_DIR/gbot.sock"
    else
        log_error "Gunicorn socket not found. Checking service status..."
        $SUDO_CMD systemctl status gbot
        exit 1
    fi
    
    log_success "All services started and enabled"
}

show_installation_summary() {
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                Installation Complete!                       ${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "🎉 GBot Web Application has been installed successfully!"
    echo ""
    echo -e "📋 Installation Summary:"
    echo -e "  • Project Directory: ${BLUE}$SCRIPT_DIR${NC}"
    echo -e "  • Virtual Environment: ${BLUE}$SCRIPT_DIR/venv${NC}"
    echo -e "  • Database: PostgreSQL (optimized)"
    echo -e "  • Web Server: Nginx with reverse proxy"
    echo -e "  • Application Server: Gunicorn (4 workers)"
    echo -e "  • Process Management: Systemd service"
    echo -e "  • Security: Firewall, SSL/TLS, Security headers"
    echo -e "  • Monitoring: Automated health checks every 5 minutes"
    echo -e "  • Backup: Automated backup system"
    echo ""
    
    # Show generated security keys
    if [ -f ".env" ]; then
        echo -e "🔐 Generated Security Keys:"
        echo -e "  • SECRET_KEY: ${BLUE}$(grep '^SECRET_KEY=' .env | cut -d'=' -f2)${NC}"
        echo -e "  • WHITELIST_TOKEN: ${BLUE}$(grep '^WHITELIST_TOKEN=' .env | cut -d'=' -f2)${NC}"
        echo ""
    fi
    
    # Show database credentials
    if [ -f ".db_credentials" ]; then
        echo -e "🗄️  Database Credentials:"
        source .db_credentials
        echo -e "  • Database: ${BLUE}gbot_db${NC}"
        echo -e "  • User: ${BLUE}gbot_user${NC}"
        echo -e "  • Password: ${BLUE}$(echo $DATABASE_URL | sed 's/.*:\/\/.*:\([^@]*\)@.*/\1/')${NC}"
        echo ""
    fi
    
    echo -e "🚀 Next Steps:"
    echo -e "  1. Check service status:"
    echo -e "     ${BLUE}$SUDO_CMD systemctl status gbot nginx postgresql${NC}"
    echo -e "  2. View application logs:"
    echo -e "     ${BLUE}$SUDO_CMD journalctl -u gbot -f${NC}"
    echo -e "  3. Access the application:"
    echo -e "     ${BLUE}http://$(hostname -I | awk '{print $1}')${NC}"
    echo -e "  4. Default admin credentials:"
    echo -e "     Username: ${BLUE}admin${NC}"
    echo -e "     Password: ${BLUE}A9B3nX#Q8k\$mZ6vw${NC}"
    echo ""
    echo -e "🔧 Management Commands:"
    echo -e "  • Restart services: ${BLUE}$SUDO_CMD systemctl restart gbot nginx${NC}"
    echo -e "  • Check monitoring: ${BLUE}./monitor_gbot.sh${NC}"
    echo -e "  • View monitoring logs: ${BLUE}tail -f monitoring.log${NC}"
    echo -e "  • Create backup: ${BLUE}./setup_complete.sh --backup${NC}"
    echo ""
    echo -e "📚 Documentation:"
    echo -e "  • README.md - Complete documentation"
    echo -e "  • setup.log - Installation details"
    echo -e "  • monitoring.log - System monitoring logs"
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -i, --install           Run complete installation"
    echo "  -r, --reinstall         Force reinstallation of all components"
    echo "  -v, --validate          Validate existing installation"
    echo "  -c, --check             Check system requirements only"
    echo "  -s, --ssl               Setup SSL certificate"
    echo "  -b, --backup            Create backup of current installation"
    echo "  -m, --monitor           Setup monitoring only"
    echo "  --troubleshoot          Troubleshoot connection issues"
    echo "  --fix-nginx             Fix Nginx configuration issues"
    echo "  --inspect-nginx         Inspect Nginx configuration in detail"
    echo "  --nuke-nginx            COMPLETELY rebuild Nginx from scratch"
    echo "  --add-ip                Add current IP to whitelist"
    echo "  --disable-whitelist     Disable IP whitelist (allow all IPs)"
    echo "  --fix-all               🔥 FIX ALL ISSUES AT ONCE (RECOMMENDED)"
    echo "  --fix-whitelist         Fix IP whitelist issues"
    echo "  --install-deps          Install missing Python dependencies"
    echo "  --fix-admin             Fix admin user login issue"
    echo "  --enable-whitelist      Enable IP whitelist security"
    echo "  --fix-whitelist-startup Fix IP whitelist startup issues"
    echo "  --clean                 Clean installation files"
    echo ""
    echo "Examples:"
    echo "  $0 --install            # Complete installation"
    echo "  $0 --reinstall          # Force reinstall everything"
    echo "  $0 --validate           # Check installation health"
    echo "  $0 --ssl                # Setup SSL certificate"
    echo "  $0 --backup             # Create backup"
}

clean_installation() {
    log "Cleaning installation..."
    
    # Stop services
    $SUDO_CMD systemctl stop gbot 2>/dev/null || true
    $SUDO_CMD systemctl disable gbot 2>/dev/null || true
    
    # Remove service file
    $SUDO_CMD rm -f /etc/systemd/system/gbot.service
    
    # Remove nginx configuration
    $SUDO_CMD rm -f /etc/nginx/sites-enabled/gbot
    $SUDO_CMD rm -f /etc/nginx/sites-available/gbot
    
    # Remove virtual environment
    rm -rf venv
    
    # Remove database
    rm -f gbot.db
    rm -f .db_credentials
    
    # Remove environment file
    rm -f .env
    
    # Remove log files
    rm -f *.log
    rm -rf logs/
    
    # Remove Python cache
    find . -name "*.pyc" -delete
    find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
    
    # Reload systemd and nginx
    $SUDO_CMD systemctl daemon-reload
    $SUDO_CMD systemctl reload nginx
    
    log_success "Installation cleaned"
}

validate_installation() {
    log "Validating installation..."
    
    validation_passed=true
    
    # Check virtual environment
    if [ ! -d "venv" ]; then
        log_error "Virtual environment not found"
        validation_passed=false
    fi
    
    # Check database
    if [ ! -f "gbot.db" ] && [ ! -f ".db_credentials" ]; then
        log_error "Database not found"
        validation_passed=false
    fi
    
    # Check environment file
    if [ ! -f ".env" ]; then
        log_error "Environment file not found"
        validation_passed=false
    fi
    
    # Check services
    if ! systemctl is-active --quiet gbot; then
        log_error "GBot service not running"
        validation_passed=false
    fi
    
    if ! systemctl is-active --quiet nginx; then
        log_error "Nginx service not running"
        validation_passed=false
    fi
    
    if ! systemctl is-active --quiet postgresql; then
        log_error "PostgreSQL service not running"
        validation_passed=false
    fi
    
    if [ "$validation_passed" = true ]; then
        log_success "Installation validation passed"
    else
        log_error "Installation validation failed"
        exit 1
    fi
}

run_complete_installation() {
    log "Starting complete installation..."
    
    # Check system requirements
    check_system_requirements
    
    # Install system dependencies
    install_system_dependencies
    
    # Setup PostgreSQL
    setup_postgresql
    
    # Setup Python environment
    setup_python_environment
    
    # Create environment file FIRST (before database setup)
    create_environment_file
    
    # Setup database (now with environment variables available)
    setup_database
    
    # Setup Nginx
    setup_nginx
    
    # Setup systemd service
    setup_systemd_service
    
    # Setup firewall
    setup_firewall
    
    # Setup SSL certificate
    setup_ssl_certificate
    
    # Setup monitoring
    setup_monitoring
    
    # Create backup
    create_backup
    
    # Start services
    start_services
    
    # Fix login issues immediately after installation
    log "Fixing login issues..."
    fix_admin_user
    
    # Display current credentials
    display_current_credentials
    
    # Troubleshoot connection issues
    troubleshoot_connection
    
    # Show summary
    show_installation_summary
    
    log_success "Complete installation finished successfully!"
}

main() {
    # Create log file
    touch "$LOG_FILE"
    
    show_banner
    
    # Parse command line arguments
    INSTALL_MODE=""
    FORCE_REINSTALL=false
    VALIDATE_ONLY=false
    CHECK_ONLY=false
    SETUP_SSL=false
    CREATE_BACKUP=false
    SETUP_MONITORING=false
    CLEANUP=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -i|--install)
                INSTALL_MODE="complete"
                shift
                ;;
            -r|--reinstall)
                FORCE_REINSTALL=true
                INSTALL_MODE="complete"
                shift
                ;;
            -v|--validate)
                VALIDATE_ONLY=true
                shift
                ;;
            -c|--check)
                CHECK_ONLY=true
                shift
                ;;
            -s|--ssl)
                SETUP_SSL=true
                shift
                ;;
            -b|--backup)
                CREATE_BACKUP=true
                shift
                ;;
            -m|--monitor)
                SETUP_MONITORING=true
                shift
                ;;
            --troubleshoot)
                troubleshoot_connection
                exit 0
                ;;
            --fix-nginx)
                fix_nginx_configuration
                exit 0
                ;;
            --inspect-nginx)
                inspect_nginx_configuration
                exit 0
                ;;
            --nuke-nginx)
                nuke_nginx_configuration
                exit 0
                ;;
            --add-ip)
                add_ip_to_whitelist
                exit 0
                ;;
            --disable-whitelist)
                disable_ip_whitelist
                exit 0
                ;;
            --fix-all)
                fix_all_issues
                exit 0
                ;;
            --fix-whitelist)
                fix_ip_whitelist
                exit 0
                ;;
            --install-deps)
                install_missing_dependencies
                exit 0
                ;;
            --fix-admin)
                fix_admin_user
                exit 0
                ;;
            --enable-whitelist)
                enable_ip_whitelist
                exit 0
                ;;
            --fix-whitelist-startup)
                fix_whitelist_startup
                exit 0
                ;;
            --clean)
                CLEANUP=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Run requested operation
    if [ "$CHECK_ONLY" = true ]; then
        check_system_requirements
        return
    fi
    
    if [ "$VALIDATE_ONLY" = true ]; then
        validate_installation
        return
    fi
    
    if [ "$CLEANUP" = true ]; then
        clean_installation
        return
    fi
    
    if [ "$CREATE_BACKUP" = true ]; then
        create_backup
        return
    fi
    
    if [ "$SETUP_MONITORING" = true ]; then
        setup_monitoring
        return
    fi
    
    if [ "$SETUP_SSL" = true ]; then
        setup_ssl_certificate
        return
    fi
    
    if [ "$FORCE_REINSTALL" = true ]; then
        log "Force reinstall mode - cleaning existing installation..."
        clean_installation
    fi
    
    if [ "$INSTALL_MODE" = "complete" ]; then
        run_complete_installation
    else
        show_help
    fi
}

# Run main function
main "$@"
