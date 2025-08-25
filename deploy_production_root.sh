#!/bin/bash

# GBot Web Application - Production Deployment Script
# This script provides a simple production deployment process

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

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

show_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    $PROJECT_NAME                    ║"
    echo "║                                                              ║"
    echo "║                Production Deployment                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_prerequisites() {
    log "Checking production prerequisites..."
    
    # Always allow root execution
    if [[ $EUID -eq 0 ]]; then
        log "Running as root user - proceeding with root deployment"
        ROOT_USER=true
        USER="root"
        USER_HOME="/root"
    else
        log "Running as regular user - will use sudo for privileged operations"
        ROOT_USER=false
    fi
    
    # Check if enhanced setup script exists
    if [ ! -f "setup_enhanced.sh" ]; then
        log_error "setup_enhanced.sh not found. Please ensure you're in the correct directory."
        exit 1
    fi
    
    # Check if install.py exists
    if [ ! -f "install.py" ]; then
        log_error "install.py not found. Please ensure you're in the correct directory."
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

get_deployment_options() {
    echo ""
    echo -e "${BLUE}Production Deployment Options:${NC}"
    echo "1. Full Production Setup (PostgreSQL + Nginx + SSL)"
    echo "2. Production Setup without SSL (Internal/Development)"
    echo "3. Production Setup with custom domain"
    echo "4. Exit"
    echo ""
    
    read -p "Select deployment option (1-4): " choice
    
    case $choice in
        1)
            DEPLOYMENT_TYPE="full"
            ;;
        2)
            DEPLOYMENT_TYPE="internal"
            ;;
        3)
            DEPLOYMENT_TYPE="custom"
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

get_custom_domain() {
    if [ "$DEPLOYMENT_TYPE" = "custom" ]; then
        echo ""
        read -p "Enter your domain name (e.g., example.com): " CUSTOM_DOMAIN
        if [ -z "$CUSTOM_DOMAIN" ]; then
            log_error "Domain name is required"
            exit 1
        fi
        log "Using custom domain: $CUSTOM_DOMAIN"
    fi
}

run_production_deployment() {
    log "Starting production deployment..."
    
    case $DEPLOYMENT_TYPE in
        "full")
            log "Running full production deployment with SSL..."
            chmod +x setup_enhanced.sh
            if [ "$ROOT_USER" = true ]; then
                ./setup_enhanced.sh --prod --ssl
            else
                sudo ./setup_enhanced.sh --prod --ssl
            fi
            ;;
        "internal")
            log "Running production deployment without SSL..."
            chmod +x setup_enhanced.sh
            if [ "$ROOT_USER" = true ]; then
                ./setup_enhanced.sh --prod
            else
                sudo ./setup_enhanced.sh --prod
            fi
            ;;
        "custom")
            log "Running production deployment with custom domain: $CUSTOM_DOMAIN"
            chmod +x setup_enhanced.sh
            if [ "$ROOT_USER" = true ]; then
                ./setup_enhanced.sh --prod
                # Update nginx configuration with custom domain
                sed -i "s/server_name _;/server_name $CUSTOM_DOMAIN;/" /etc/nginx/sites-available/gbot
                nginx -t && systemctl reload nginx
            else
                sudo ./setup_enhanced.sh --prod
                # Update nginx configuration with custom domain
                sudo sed -i "s/server_name _;/server_name $CUSTOM_DOMAIN;/" /etc/nginx/sites-available/gbot
                sudo nginx -t && sudo systemctl reload nginx
            fi
            log_success "Custom domain configured: $CUSTOM_DOMAIN"
            ;;
    esac
}

setup_monitoring() {
    log "Setting up basic monitoring..."
    
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
    log "Monitoring script: monitor_gbot.sh"
    log "Cron job: Every 5 minutes"
}

create_production_summary() {
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                Production Deployment Complete!               ${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "🎉 GBot Web Application has been deployed to production!"
    echo ""
    echo -e "📋 Deployment Summary:"
    echo -e "  • Type: ${BLUE}$DEPLOYMENT_TYPE${NC}"
    if [ "$DEPLOYMENT_TYPE" = "custom" ]; then
        echo -e "  • Domain: ${BLUE}$CUSTOM_DOMAIN${NC}"
    fi
    echo -e "  • Database: PostgreSQL (optimized)"
    echo -e "  • Web Server: Nginx with reverse proxy"
    echo -e "  • Application Server: Gunicorn (4 workers)"
    echo -e "  • Process Management: Systemd service"
    echo -e "  • Security: Firewall, SSL/TLS, Security headers"
    echo ""
    echo -e "🚀 Next Steps:"
    echo -e "  1. Check service status:"
    echo -e "     ${BLUE}sudo systemctl status gbot nginx postgresql${NC}"
    echo -e "  2. View application logs:"
    echo -e "     ${BLUE}sudo journalctl -u gbot -f${NC}"
    echo -e "  3. Access the application:"
    if [ "$DEPLOYMENT_TYPE" = "custom" ]; then
        echo -e "     ${BLUE}https://$CUSTOM_DOMAIN${NC}"
    else
        echo -e "     ${BLUE}http://your-server-ip${NC}"
    fi
    echo -e "  4. Default admin credentials:"
    echo -e "     Username: ${BLUE}admin${NC}"
    echo -e "     Password: ${BLUE}A9B3nX#Q8k\$mZ6vw${NC}"
    echo ""
    echo -e "🔧 Management Commands:"
    echo -e "  • Restart services: ${BLUE}sudo systemctl restart gbot nginx${NC}"
    echo -e "  • Check monitoring: ${BLUE}./monitor_gbot.sh${NC}"
    echo -e "  • View monitoring logs: ${BLUE}tail -f monitoring.log${NC}"
    echo -e "  • Create backup: ${BLUE}./setup_enhanced.sh --backup${NC}"
    echo ""
    echo -e "📚 Documentation:"
    echo -e "  • README.md - Complete documentation"
    echo -e "  • install.log - Installation details"
    echo -e "  • monitoring.log - System monitoring logs"
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
}

main() {
    show_banner
    
    # Check prerequisites
    check_prerequisites
    
    # Get deployment options
    get_deployment_options
    
    # Get custom domain if needed
    get_custom_domain
    
    # Confirm deployment
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
    
    # Run deployment
    run_production_deployment
    
    # Setup monitoring
    setup_monitoring
    
    # Show summary
    create_production_summary
    
    log_success "Production deployment completed successfully!"
}

# Run main function
main "$@"
