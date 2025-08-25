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
    
    # Check pip
    if command -v pip3 &> /dev/null; then
        log_success "pip3 is available"
    else
        log_error "pip3 is not available"
        exit 1
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
        $SUDO_CMD apt-get install -y python3-pip python3-dev python3-venv build-essential libssl-dev libffi-dev python3-setuptools
        $SUDO_CMD apt-get install -y postgresql postgresql-contrib
        $SUDO_CMD apt-get install -y nginx
        $SUDO_CMD apt-get install -y ufw
        $SUDO_CMD apt-get install -y certbot python3-certbot-nginx
        $SUDO_CMD apt-get install -y curl wget git
    elif command -v yum &> /dev/null; then
        log "Using yum package manager"
        $SUDO_CMD yum update -y
        $SUDO_CMD yum install -y python3-pip python3-devel gcc openssl-devel libffi-devel python3-setuptools
        $SUDO_CMD yum install -y postgresql postgresql-server postgresql-contrib
        $SUDO_CMD yum install -y nginx
        $SUDO_CMD yum install -y firewalld
        $SUDO_CMD yum install -y curl wget git
    elif command -v dnf &> /dev/null; then
        log "Using dnf package manager"
        $SUDO_CMD dnf update -y
        $SUDO_CMD dnf install -y python3-pip python3-devel gcc openssl-devel libffi-devel python3-setuptools
        $SUDO_CMD dnf install -y postgresql postgresql-server postgresql-contrib
        $SUDO_CMD dnf install -y nginx
        $SUDO_CMD dnf install -y firewalld
        $SUDO_CMD dnf install -y curl wget git
    else
        log_error "Unsupported package manager"
        exit 1
    fi
    
    log_success "System dependencies installed"
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
with app.app_context():
    db.create_all()
    print('Database tables created successfully')
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

# Google API Configuration
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# Application Settings
DEBUG=False
FLASK_ENV=production
LOG_LEVEL=INFO

# Production Settings
SESSION_COOKIE_SECURE=True
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
    }
    
    location /static {
        alias $SCRIPT_DIR/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
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
        log_success "Nginx configuration completed"
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
    
    # Display current credentials
    display_current_credentials
    
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
