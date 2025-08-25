#!/bin/bash

# GBot Web Application - Quick Start Script
# This script provides a simple one-command installation

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
    echo "║                    Quick Start                               ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -d, --dev               Development setup (SQLite)"
    echo "  -p, --prod              Production setup (PostgreSQL + Nginx)"
    echo "  -f, --fast              Fast installation (skip some checks)"
    echo "  -q, --quiet             Quiet mode (minimal output)"
    echo ""
    echo "Examples:"
    echo "  $0                      # Interactive installation"
    echo "  $0 --dev               # Development setup"
    echo "  $0 --prod              # Production setup"
    echo "  $0 --fast              # Fast installation"
}

check_ubuntu() {
    if [ ! -f /etc/os-release ]; then
        log_error "This script is designed for Ubuntu/Linux systems only"
        exit 1
    fi
    
    source /etc/os-release
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" && "$ID" != "linuxmint" ]]; then
        log_warning "This script is tested on Ubuntu. Other distributions may work but are not guaranteed."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

check_python() {
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        log "Installing Python 3..."
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip python3-venv
        log_success "Python 3 installed"
    fi
    
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PYTHON_VERSION_NUM=$(python3 -c "import sys; print(sys.version_info.major * 100 + sys.version_info.minor)")
    
    if [ $PYTHON_VERSION_NUM -lt 308 ]; then
        log_error "Python version $PYTHON_VERSION is below minimum required version 3.8"
        log "Upgrading Python..."
        sudo apt-get install -y python3.8 python3.8-pip python3.8-venv
        log_success "Python 3.8 installed"
    else
        log_success "Python $PYTHON_VERSION is compatible"
    fi
}

install_system_dependencies() {
    log "Installing system dependencies..."
    
    sudo apt-get update
    sudo apt-get install -y \
        python3-pip \
        python3-dev \
        python3-venv \
        build-essential \
        libssl-dev \
        libffi-dev \
        sqlite3
    
    log_success "System dependencies installed"
}

run_installation() {
    local mode="$1"
    local fast="$2"
    
    log "Starting GBot installation in $mode mode..."
    
    if [ "$fast" = true ]; then
        log_warning "Fast mode enabled - skipping some validation steps"
    fi
    
    # Check if Python installer exists
    if [ -f "install.py" ]; then
        log "Using Python installer..."
        if [ "$mode" = "prod" ]; then
            python3 install.py --reinstall
        else
            python3 install.py
        fi
    else
        log_error "install.py not found. Please ensure you're in the correct directory."
        exit 1
    fi
    
    # Run enhanced setup if available
    if [ -f "setup_enhanced.sh" ] && [ "$mode" = "prod" ]; then
        log "Running enhanced production setup..."
        chmod +x setup_enhanced.sh
        ./setup_enhanced.sh --prod
    fi
}

post_installation_setup() {
    log "Setting up post-installation configuration..."
    
    # Make scripts executable
    chmod +x *.sh *.py 2>/dev/null || true
    
    # Create startup script
    cat > start_gbot.sh << 'EOF'
#!/bin/bash
# GBot Web Application Startup Script

cd "$(dirname "$0")"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Please run the installation first."
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Start the application
echo "Starting GBot Web Application..."
echo "Access the application at: http://localhost:5000"
echo "Default credentials: admin / A9B3nX#Q8k\$mZ6vw"
echo ""
echo "Press Ctrl+C to stop the application"
echo ""

python3 app.py
EOF
    
    chmod +x start_gbot.sh
    log_success "Startup script created: start_gbot.sh"
}

show_success_message() {
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                    Installation Complete!                    ${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "🎉 GBot Web Application has been installed successfully!"
    echo ""
    echo -e "📋 Quick Start:"
    echo -e "  1. Start the application: ${BLUE}./start_gbot.sh${NC}"
    echo -e "  2. Or manually: ${BLUE}source venv/bin/activate && python3 app.py${NC}"
    echo -e "  3. Access at: ${BLUE}http://localhost:5000${NC}"
    echo -e "  4. Login with: ${BLUE}admin${NC} / ${BLUE}A9B3nX#Q8k\$mZ6vw${NC}"
    echo ""
    echo -e "🔧 Management:"
    echo -e "  • Check installation: ${BLUE}./install_checklist.sh${NC}"
    echo -e "  • Validate: ${BLUE}python3 install.py --validate${NC}"
    echo -e "  • Reinstall: ${BLUE}python3 install.py --reinstall${NC}"
    echo ""
    echo -e "📚 Documentation:"
    echo -e "  • README.md - Complete documentation"
    echo -e "  • install.log - Installation details"
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
}

main() {
    show_banner
    
    # Parse command line arguments
    INSTALL_MODE="dev"
    FAST_MODE=false
    QUIET_MODE=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -d|--dev)
                INSTALL_MODE="dev"
                shift
                ;;
            -p|--prod)
                INSTALL_MODE="prod"
                shift
                ;;
            -f|--fast)
                FAST_MODE=true
                shift
                ;;
            -q|--quiet)
                QUIET_MODE=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Check system requirements
    log "Checking system requirements..."
    check_ubuntu
    check_python
    
    # Install system dependencies
    install_system_dependencies
    
    # Run installation
    run_installation "$INSTALL_MODE" "$FAST_MODE"
    
    # Post-installation setup
    post_installation_setup
    
    # Show success message
    show_success_message
}

# Run main function
main "$@"
