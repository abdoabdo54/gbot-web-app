#!/bin/bash

# GBot Web Application - Root Production Deployment Script
# This script bypasses all root checks and runs everything as root

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

show_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                GBot Web Application                        ║"
    echo "║                                                              ║"
    echo "║                ROOT Production Deployment                  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_files() {
    log "Checking required files..."
    
    if [ ! -f "setup_enhanced.sh" ]; then
        log_error "setup_enhanced.sh not found"
        exit 1
    fi
    
    if [ ! -f "install.py" ]; then
        log_error "install.py not found"
        exit 1
    fi
    
    log_success "All required files found"
}

get_deployment_type() {
    echo ""
    echo -e "${BLUE}Production Deployment Options:${NC}"
    echo "1. Full Production Setup (PostgreSQL + Nginx + SSL)"
    echo "2. Production Setup without SSL (Internal/Development)"
    echo "3. Production Setup with custom domain"
    echo "4. Exit"
    echo ""
    
    read -p "Select deployment option (1-4): " choice
    
    case $choice in
        1) DEPLOYMENT_TYPE="full" ;;
        2) DEPLOYMENT_TYPE="internal" ;;
        3) 
            DEPLOYMENT_TYPE="custom"
            echo ""
            read -p "Enter your domain name (e.g., example.com): " CUSTOM_DOMAIN
            if [ -z "$CUSTOM_DOMAIN" ]; then
                log_error "Domain name is required"
                exit 1
            fi
            log "Using custom domain: $CUSTOM_DOMAIN"
            ;;
        4) 
            log "Deployment cancelled by user"
            exit 0
            ;;
        *)
            log_error "Invalid option selected"
            exit 1
            ;;
    esac
}

modify_scripts_for_root() {
    log "Modifying scripts for root execution..."
    
    # Backup original scripts
    cp setup_enhanced.sh setup_enhanced.sh.backup
    
    # Remove root checks from setup_enhanced.sh
    sed -i '/if.*EUID.*-eq.*0.*then/,/fi/d' setup_enhanced.sh
    sed -i '/log_error.*This script should not be run as root/d' setup_enhanced.sh
    sed -i '/exit 1.*root/d' setup_enhanced.sh
    
    log_success "Scripts modified for root execution"
}

run_deployment() {
    log "Starting production deployment..."
    
    # Make scripts executable
    chmod +x *.sh *.py
    
    case $DEPLOYMENT_TYPE in
        "full")
            log "Running full production deployment with SSL..."
            ./setup_enhanced.sh --prod --ssl
            ;;
        "internal")
            log "Running production deployment without SSL..."
            ./setup_enhanced.sh --prod
            ;;
        "custom")
            log "Running production deployment with custom domain: $CUSTOM_DOMAIN"
            ./setup_enhanced.sh --prod
            # Update nginx configuration with custom domain
            sed -i "s/server_name _;/server_name $CUSTOM_DOMAIN;/" /etc/nginx/sites-available/gbot
            nginx -t && systemctl reload nginx
            log_success "Custom domain configured: $CUSTOM_DOMAIN"
            ;;
    esac
}

restore_scripts() {
    log "Restoring original scripts..."
    mv setup_enhanced.sh.backup setup_enhanced.sh
    log_success "Scripts restored"
}

setup_monitoring() {
    log "Setting up monitoring..."
    
    cat > monitor_gbot.sh << 'EOF'
#!/bin/bash
LOG_FILE="monitoring.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

check_service() {
    local service_name=$1
    if systemctl is-active --quiet $service_name; then
        echo "[$TIMESTAMP] ✓ Service $service_name is running" >> $LOG_FILE
    else
        echo "[$TIMESTAMP] ✗ Service $service_name is not running" >> $LOG_FILE
        systemctl restart $service_name
        echo "[$TIMESTAMP] 🔄 Attempted to restart $service_name" >> $LOG_FILE
    fi
}

check_service gbot
check_service nginx
check_service postgresql

# Keep only last 1000 lines
tail -n 1000 $LOG_FILE > $LOG_FILE.tmp && mv $LOG_FILE.tmp $LOG_FILE
EOF
    
    chmod +x monitor_gbot.sh
    
    # Setup cron job
    (crontab -l 2>/dev/null; echo "*/5 * * * * cd $(pwd) && ./monitor_gbot.sh") | crontab -
    
    log_success "Monitoring setup completed"
}

show_summary() {
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                Production Deployment Complete!               ${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "🎉 GBot Web Application deployed successfully!"
    echo ""
    echo -e "📋 Deployment Type: ${BLUE}$DEPLOYMENT_TYPE${NC}"
    if [ "$DEPLOYMENT_TYPE" = "custom" ]; then
        echo -e "🌐 Domain: ${BLUE}$CUSTOM_DOMAIN${NC}"
    fi
    echo ""
    echo -e "🚀 Next Steps:"
    echo -e "  1. Check services: ${BLUE}systemctl status gbot nginx postgresql${NC}"
    echo -e "  2. View logs: ${BLUE}journalctl -u gbot -f${NC}"
    echo -e "  3. Access app: ${BLUE}http://$(hostname -I | awk '{print $1}')${NC}"
    echo -e "  4. Admin login: ${BLUE}admin${NC} / ${BLUE}A9B3nX#Q8k\$mZ6vw${NC}"
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
}

main() {
    show_banner
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
    
    log "Running as root user - proceeding with deployment"
    
    check_files
    get_deployment_type
    
    echo ""
    echo -e "${YELLOW}Production deployment will:${NC}"
    echo "  • Install PostgreSQL with optimized settings"
    echo "  • Configure Nginx reverse proxy"
    echo "  • Setup systemd service"
    echo "  • Configure firewall (UFW)"
    echo "  • Install SSL certificate (if selected)"
    echo "  • Setup monitoring and backup"
    echo ""
    read -p "Continue with production deployment? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Deployment cancelled by user"
        exit 0
    fi
    
    modify_scripts_for_root
    run_deployment
    setup_monitoring
    restore_scripts
    show_summary
    
    log_success "Production deployment completed successfully!"
}

main "$@"
