#!/bin/bash

# GBot Web Application - Enhanced Setup Script
# This script provides comprehensive installation options for Linux/Unix systems

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
VERSION="1.0.0"
MIN_PYTHON_VERSION="3.8"
MIN_DISK_SPACE_GB="1"
MIN_MEMORY_GB="0.5"

# Logging
LOG_FILE="$SCRIPT_DIR/setup.log"
exec > >(tee -a "$LOG_FILE") 2>&1

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    $PROJECT_NAME                    ║"
    echo "║                        v$VERSION                              ║"
    echo "║                                                              ║"
    echo "║              Enhanced Installation Script                     ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -i, --install           Run full installation"
    echo "  -r, --reinstall         Force reinstallation"
    echo "  -v, --validate          Validate existing installation"
    echo "  -c, --check             Check system prerequisites only"
    echo "  -d, --dev               Development installation (SQLite)"
    echo "  -p, --prod              Production installation (PostgreSQL)"
    echo "  -s, --systemd           Install systemd service"
    echo "  -n, --nginx             Install nginx configuration"
    echo "  -u, --update            Update existing installation"
    echo "  --clean                 Clean installation files"
    echo "  --ssl                   Setup SSL certificate with Let's Encrypt"
    echo "  --backup                Create backup of current installation"
    echo "  --monitor               Setup monitoring and health checks"
    echo ""
    echo "Examples:"
    echo "  $0 --install            # Full installation"
    echo "  $0 --dev               # Development setup"
    echo "  $0 --prod              # Production setup"
    echo "  $0 --validate          # Check installation health"
    echo "  $0 --reinstall         # Force reinstall"
    echo "  $0 --ssl               # Setup SSL certificate"
    echo "  $0 --backup            # Create backup"
}

check_system_requirements() {
    log "Checking system requirements..."
    
    # Check OS
    if [[ "$OSTYPE" != "linux-gnu"* ]] && [[ "$OSTYPE" != "darwin"* ]]; then
        log_error "Unsupported operating system: $OSTYPE"
        log_error "This script supports Linux and macOS only"
        exit 1
    fi
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        log_warning "Running as root. This is not recommended for security reasons."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Check Python version
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PYTHON_VERSION_NUM=$(python3 -c "import sys; print(sys.version_info.major * 100 + sys.version_info.minor)")
    MIN_VERSION_NUM=$(echo $MIN_PYTHON_VERSION | sed 's/\.//')
    
    if [ $PYTHON_VERSION_NUM -lt $MIN_VERSION_NUM ]; then
        log_error "Python version $PYTHON_VERSION is below minimum required version $MIN_PYTHON_VERSION"
        exit 1
    fi
    
    log_success "Python $PYTHON_VERSION is compatible"
    
    # Check disk space
    AVAILABLE_SPACE=$(df "$SCRIPT_DIR" | awk 'NR==2 {print $4}')
    AVAILABLE_SPACE_GB=$((AVAILABLE_SPACE / 1024 / 1024))
    
    if [ $AVAILABLE_SPACE_GB -lt $MIN_DISK_SPACE_GB ]; then
        log_error "Insufficient disk space: ${AVAILABLE_SPACE_GB}GB available, ${MIN_DISK_SPACE_GB}GB required"
        exit 1
    fi
    
    log_success "Disk space: ${AVAILABLE_SPACE_GB}GB available"
    
    # Check memory
    if command -v free &> /dev/null; then
        AVAILABLE_MEMORY=$(free -g | awk 'NR==2 {print $7}')
        if [ $AVAILABLE_MEMORY -lt $(echo $MIN_MEMORY_GB | cut -d. -f1) ]; then
            log_warning "Low memory: ${AVAILABLE_MEMORY}GB available, ${MIN_MEMORY_GB}GB recommended"
        else
            log_success "Memory: ${AVAILABLE_MEMORY}GB available"
        fi
    fi
    
    # Check internet connection
    if ! ping -c 1 pypi.org &> /dev/null; then
        log_warning "No internet connection detected. Some features may not work."
    else
        log_success "Internet connection available"
    fi
    
    log_success "System requirements check passed"
}

detect_existing_installation() {
    log "Detecting existing installation..."
    
    EXISTING_COMPONENTS=()
    
    # Check for Python virtual environment
    if [ -d "$SCRIPT_DIR/venv" ]; then
        EXISTING_COMPONENTS+=("Python virtual environment")
    fi
    
    # Check for database
    if [ -f "$SCRIPT_DIR/gbot.db" ]; then
        EXISTING_COMPONENTS+=("SQLite database")
    fi
    
    # Check for environment file
    if [ -f "$SCRIPT_DIR/.env" ]; then
        EXISTING_COMPONENTS+=("Environment configuration")
    fi
    
    # Check for systemd service
    if [ -f "/etc/systemd/system/gbot.service" ]; then
        EXISTING_COMPONENTS+=("Systemd service")
    fi
    
    # Check for nginx configuration
    if [ -f "/etc/nginx/sites-available/gbot" ]; then
        EXISTING_COMPONENTS+=("Nginx configuration")
    fi
    
    if [ ${#EXISTING_COMPONENTS[@]} -gt 0 ]; then
        log_warning "Existing installation components detected:"
        for component in "${EXISTING_COMPONENTS[@]}"; do
            echo "  - $component"
        done
        return 1
    else
        log_success "No existing installation detected"
        return 0
    fi
}

install_system_dependencies() {
    log "Installing system dependencies..."
    
    # Detect package manager
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt-get"
        UPDATE_CMD="sudo apt-get update"
        INSTALL_CMD="sudo apt-get install -y"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        UPDATE_CMD="sudo yum update -y"
        INSTALL_CMD="sudo yum install -y"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        UPDATE_CMD="sudo dnf update -y"
        INSTALL_CMD="sudo dnf install -y"
    elif command -v pacman &> /dev/null; then
        PKG_MANAGER="pacman"
        UPDATE_CMD="sudo pacman -Sy"
        INSTALL_CMD="sudo pacman -S --noconfirm"
    else
        log_error "Unsupported package manager. Please install dependencies manually."
        return 1
    fi
    
    log "Using package manager: $PKG_MANAGER"
    
    # Update package lists
    log "Updating package lists..."
    eval $UPDATE_CMD
    
    # Install Python development tools
    log "Installing Python development tools..."
    if [ "$PKG_MANAGER" = "apt-get" ]; then
        eval $INSTALL_CMD python3-pip python3-dev python3-venv build-essential libssl-dev libffi-dev
    elif [ "$PKG_MANAGER" = "yum" ] || [ "$PKG_MANAGER" = "dnf" ]; then
        eval $INSTALL_CMD python3-pip python3-devel python3-venv gcc openssl-devel libffi-devel
    elif [ "$PKG_MANAGER" = "pacman" ]; then
        eval $INSTALL_CMD python-pip python-virtualenv base-devel openssl libffi
    fi
    
    log_success "System dependencies installed"
}

setup_postgresql() {
    log "Setting up PostgreSQL database..."
    
    # Check if PostgreSQL is already running
    if systemctl is-active --quiet postgresql; then
        log "PostgreSQL is already running"
    else
        # Install PostgreSQL
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y postgresql postgresql-contrib
        elif command -v yum &> /dev/null; then
            sudo yum install -y postgresql postgresql-server postgresql-contrib
            sudo postgresql-setup initdb
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y postgresql postgresql-server postgresql-contrib
            sudo postgresql-setup initdb
        fi
        
        # Start PostgreSQL service
        sudo systemctl start postgresql
        sudo systemctl enable postgresql
    fi
    
    # Configure PostgreSQL for production
    log "Configuring PostgreSQL for production..."
    sudo -u postgres psql -c "ALTER SYSTEM SET max_connections = '100';"
    sudo -u postgres psql -c "ALTER SYSTEM SET shared_buffers = '256MB';"
    sudo -u postgres psql -c "ALTER SYSTEM SET effective_cache_size = '1GB';"
    sudo -u postgres psql -c "ALTER SYSTEM SET maintenance_work_mem = '64MB';"
    sudo -u postgres psql -c "ALTER SYSTEM SET checkpoint_completion_target = '0.9';"
    sudo -u postgres psql -c "ALTER SYSTEM SET wal_buffers = '16MB';"
    sudo -u postgres psql -c "ALTER SYSTEM SET default_statistics_target = '100';"
    
    # Restart PostgreSQL to apply changes
    sudo systemctl restart postgresql
    
    # Create database and user
    DB_NAME="gbot_db"
    DB_USER="gbot_user"
    DB_PASS=$(openssl rand -hex 12)
    
    # Check if database exists
    if sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
        log "Database '$DB_NAME' already exists"
    else
        log "Creating database '$DB_NAME'..."
        sudo -u postgres psql -c "CREATE DATABASE $DB_NAME;"
    fi
    
    # Check if user exists
    if sudo -u postgres psql -t -c "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1; then
        log "User '$DB_USER' already exists"
    else
        log "Creating user '$DB_USER'..."
        sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
    fi
    
    # Grant privileges
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
    
    # Save database credentials
    echo "DATABASE_URL=postgresql://$DB_USER:$DB_PASS@localhost/$DB_NAME" >> "$SCRIPT_DIR/.env"
    
    log_success "PostgreSQL setup completed"
    log "Database credentials saved to .env file"
}

setup_nginx() {
    log "Setting up Nginx reverse proxy..."
    
    # Install nginx if not present
    if ! command -v nginx &> /dev/null; then
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y nginx
        elif command -v yum &> /dev/null; then
            sudo yum install -y nginx
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y nginx
        fi
    fi
    
    # Install certbot for SSL certificates
    if command -v apt-get &> /dev/null; then
        sudo apt-get install -y certbot python3-certbot-nginx
    fi
    
    # Create nginx configuration
    NGINX_CONFIG="/etc/nginx/sites-available/gbot"
    NGINX_ENABLED="/etc/nginx/sites-enabled/gbot"
    
    if [ -f "$NGINX_CONFIG" ]; then
        log "Nginx configuration already exists"
    else
        log "Creating nginx configuration..."
        
        cat > "$NGINX_CONFIG" << EOF
server {
    listen 80;
    server_name _;
    
    location / {
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
        
        # Enable site
        sudo ln -sf "$NGINX_CONFIG" "$NGINX_ENABLED"
        
        # Test configuration
        if sudo nginx -t; then
            sudo systemctl reload nginx
            log_success "Nginx configuration created and enabled"
        else
            log_error "Nginx configuration test failed"
            return 1
        fi
    fi
}

setup_systemd_service() {
    log "Setting up systemd service..."
    
    SERVICE_FILE="/etc/systemd/system/gbot.service"
    
    if [ -f "$SERVICE_FILE" ]; then
        log "Systemd service already exists"
    else
        log "Creating systemd service..."
        
        cat > "$SERVICE_FILE" << EOF
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
        
        # Reload systemd and enable service
        sudo systemctl daemon-reload
        sudo systemctl enable gbot
        
        log_success "Systemd service created and enabled"
    fi
}

setup_ssl_certificate() {
    log "Setting up SSL certificate with Let's Encrypt..."
    
    if ! command -v certbot &> /dev/null; then
        log_error "Certbot not found. Please install it first."
        return 1
    fi
    
    read -p "Enter your domain name (e.g., example.com): " DOMAIN_NAME
    if [ -z "$DOMAIN_NAME" ]; then
        log_error "Domain name is required for SSL setup"
        return 1
    fi
    
    log "Setting up SSL certificate for $DOMAIN_NAME..."
    
    # Update nginx configuration with domain
    sudo sed -i "s/server_name _;/server_name $DOMAIN_NAME;/" /etc/nginx/sites-available/gbot
    
    # Test nginx configuration
    if sudo nginx -t; then
        sudo systemctl reload nginx
        
        # Obtain SSL certificate
        sudo certbot --nginx -d $DOMAIN_NAME --non-interactive --agree-tos --email admin@$DOMAIN_NAME
        
        log_success "SSL certificate setup completed for $DOMAIN_NAME"
    else
        log_error "Nginx configuration test failed"
        return 1
    fi
}

create_backup() {
    log "Creating backup of current installation..."
    
    BACKUP_DIR="$SCRIPT_DIR/backups"
    BACKUP_NAME="gbot_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    
    mkdir -p "$BACKUP_DIR"
    
    # Create backup excluding unnecessary files
    tar --exclude='venv' --exclude='*.pyc' --exclude='__pycache__' --exclude='logs/*.log' \
        -czf "$BACKUP_DIR/$BACKUP_NAME" -C "$SCRIPT_DIR" .
    
    log_success "Backup created: $BACKUP_DIR/$BACKUP_NAME"
}

run_python_installer() {
    log "Running Python installer..."
    
    cd "$SCRIPT_DIR"
    
    if [ "$1" = "--reinstall" ]; then
        python3 install.py --reinstall
    elif [ "$1" = "--validate" ]; then
        python3 install.py --validate
    else
        python3 install.py
    fi
    
    if [ $? -eq 0 ]; then
        log_success "Python installation completed"
        return 0
    else
        log_error "Python installation failed"
        return 1
    fi
}

cleanup_installation() {
    log "Cleaning up installation files..."
    
    # Remove temporary files
    rm -f "$SCRIPT_DIR/setup.log"
    rm -f "$SCRIPT_DIR/install.log"
    rm -f "$SCRIPT_DIR/install_config.json"
    
    # Remove Python cache
    find "$SCRIPT_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "$SCRIPT_DIR" -name "*.pyc" -delete 2>/dev/null || true
    
    log_success "Cleanup completed"
}

show_installation_summary() {
    echo -e "\n${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                    Installation Summary                    ${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "📁 Project Directory: ${BLUE}$SCRIPT_DIR${NC}"
    echo -e "🐍 Python Environment: ${BLUE}$SCRIPT_DIR/venv${NC}"
    echo -e "🗄️  Database: ${BLUE}$SCRIPT_DIR/gbot.db${NC}"
    echo -e "⚙️  Configuration: ${BLUE}$SCRIPT_DIR/.env${NC}"
    echo -e "📋 Log Files: ${BLUE}$SCRIPT_DIR/setup.log${NC}"
    echo ""
    echo -e "🚀 Next Steps:"
    echo -e "  1. Activate virtual environment:"
    echo -e "     ${BLUE}source $SCRIPT_DIR/venv/bin/activate${NC}"
    echo -e "  2. Start the application:"
    echo -e "     ${BLUE}python $SCRIPT_DIR/app.py${NC}"
    echo -e "  3. Access at: ${BLUE}http://localhost:5000${NC}"
    echo ""
    echo -e "🔑 Default Admin Credentials:"
    echo -e "    Username: ${BLUE}admin${NC}"
    echo -e "    Password: ${BLUE}A9B3nX#Q8k$mZ6vw${NC}"
    echo ""
    echo -e "📚 Documentation:"
    echo -e "   • Check README.md for detailed usage"
    echo -e "   • Review log files for troubleshooting"
    echo ""
    echo -e "🔧 Management Commands:"
    echo -e "   • Validate: ${BLUE}$0 --validate${NC}"
    echo -e "   • Reinstall: ${BLUE}$0 --reinstall${NC}"
    echo -e "   • Check health: ${BLUE}$0 --check${NC}"
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
}

main() {
    show_banner
    
    # Parse command line arguments
    INSTALL_MODE=""
    FORCE_REINSTALL=false
    VALIDATE_ONLY=false
    CHECK_ONLY=false
    SETUP_SYSTEMD=false
    SETUP_NGINX=false
    SETUP_POSTGRESQL=false
    CLEANUP=false
    SETUP_SSL=false
    CREATE_BACKUP=false
    SETUP_MONITORING=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -i|--install)
                INSTALL_MODE="install"
                shift
                ;;
            -r|--reinstall)
                INSTALL_MODE="reinstall"
                FORCE_REINSTALL=true
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
            -d|--dev)
                INSTALL_MODE="dev"
                shift
                ;;
            -p|--prod)
                INSTALL_MODE="prod"
                SETUP_POSTGRESQL=true
                SETUP_SYSTEMD=true
                SETUP_NGINX=true
                shift
                ;;
            -s|--systemd)
                SETUP_SYSTEMD=true
                shift
                ;;
            -n|--nginx)
                SETUP_NGINX=true
                shift
                ;;
            -u|--update)
                INSTALL_MODE="update"
                shift
                ;;
            --clean)
                CLEANUP=true
                shift
                ;;
            --ssl)
                SETUP_SSL=true
                shift
                ;;
            --backup)
                CREATE_BACKUP=true
                shift
                ;;
            --monitor)
                SETUP_MONITORING=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Default to install if no mode specified
    if [ -z "$INSTALL_MODE" ] && [ "$VALIDATE_ONLY" = false ] && [ "$CHECK_ONLY" = false ] && [ "$CLEANUP" = false ]; then
        INSTALL_MODE="install"
    fi
    
    # Check system requirements
    check_system_requirements
    
    # Handle different modes
    if [ "$CHECK_ONLY" = true ]; then
        log "System check completed successfully"
        exit 0
    fi
    
    if [ "$VALIDATE_ONLY" = true ]; then
        run_python_installer --validate
        exit $?
    fi
    
    if [ "$CLEANUP" = true ]; then
        cleanup_installation
        exit 0
    fi
    
    # Detect existing installation
    if detect_existing_installation; then
        if [ "$FORCE_REINSTALL" = false ]; then
            log "Fresh installation mode"
        fi
    else
        if [ "$FORCE_REINSTALL" = false ]; then
            read -p "Existing installation detected. Continue with installation? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log "Installation aborted by user"
                exit 0
            fi
        fi
    fi
    
    # Install system dependencies
    install_system_dependencies
    
    # Run Python installer
    if [ "$INSTALL_MODE" = "reinstall" ]; then
        run_python_installer --reinstall
    else
        run_python_installer
    fi
    
    if [ $? -ne 0 ]; then
        log_error "Installation failed"
        exit 1
    fi
    
    # Setup additional components based on mode
    if [ "$SETUP_POSTGRESQL" = true ]; then
        setup_postgresql
    fi
    
    if [ "$SETUP_SYSTEMD" = true ]; then
        setup_systemd_service
    fi
    
    if [ "$SETUP_NGINX" = true ]; then
        setup_nginx
    fi
    
    # Setup SSL if requested
    if [ "$SETUP_SSL" = true ]; then
        setup_ssl_certificate
    fi
    
    # Create backup if requested
    if [ "$CREATE_BACKUP" = true ]; then
        create_backup
    fi
    
    # Show installation summary
    show_installation_summary
    
    log_success "Installation completed successfully!"
}

# Run main function with all arguments
main "$@"
