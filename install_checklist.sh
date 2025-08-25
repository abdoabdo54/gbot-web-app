#!/bin/bash

# GBot Web Application - Installation Checklist
# This script helps verify each step of the installation process

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
    echo "║              Installation Checklist                          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_step() {
    local step_name="$1"
    local check_command="$2"
    local fix_command="$3"
    
    echo -n "Checking: $step_name... "
    
    if eval "$check_command" >/dev/null 2>&1; then
        log_success "$step_name"
        return 0
    else
        log_error "$step_name"
        if [ -n "$fix_command" ]; then
            echo -e "${YELLOW}  Fix command: $fix_command${NC}"
        fi
        return 1
    fi
}

run_installation_checklist() {
    show_banner
    
    echo "This checklist will verify each step of your GBot installation."
    echo "Run this after completing the installation to ensure everything is working."
    echo ""
    
    local all_passed=true
    local step_count=0
    local passed_count=0
    
    # Step 1: Check if we're in the right directory
    step_count=$((step_count + 1))
    if check_step "Project Directory" "[ -f 'app.py' ]" "cd /path/to/gbot-web-app"; then
        passed_count=$((passed_count + 1))
    else
        all_passed=false
    fi
    
    # Step 2: Check Python version
    step_count=$((step_count + 1))
    if check_step "Python 3.8+" "python3 -c 'import sys; exit(0 if sys.version_info >= (3,8) else 1)'" "sudo apt-get install python3.8"; then
        passed_count=$((passed_count + 1))
    else
        all_passed=false
    fi
    
    # Step 3: Check virtual environment
    step_count=$((step_count + 1))
    if check_step "Virtual Environment" "[ -d 'venv' ]" "python3 -m venv venv"; then
        passed_count=$((passed_count + 1))
    else
        all_passed=false
    fi
    
    # Step 4: Check if virtual environment is activated
    step_count=$((step_count + 1))
    if check_step "Virtual Environment Activated" "[ -n \"\$VIRTUAL_ENV\" ]" "source venv/bin/activate"; then
        passed_count=$((passed_count + 1))
    else
        all_passed=false
    fi
    
    # Step 5: Check Python executable in venv
    step_count=$((step_count + 1))
    if check_step "Python in Virtual Environment" "[ -f 'venv/bin/python' ]" "python3 -m venv venv"; then
        passed_count=$((passed_count + 1))
    else
        all_passed=false
    fi
    
    # Step 6: Check pip in venv
    step_count=$((step_count + 1))
    if check_step "Pip in Virtual Environment" "[ -f 'venv/bin/pip' ]" "python3 -m venv venv"; then
        passed_count=$((passed_count + 1))
    else
        all_passed=false
    fi
    
    # Step 7: Check requirements.txt
    step_count=$((step_count + 1))
    if check_step "Requirements File" "[ -f 'requirements.txt' ]" "Create requirements.txt with dependencies"; then
        passed_count=$((passed_count + 1))
    else
        all_passed=false
    fi
    
    # Step 8: Check if dependencies are installed
    step_count=$((step_count + 1))
    if check_step "Dependencies Installed" "venv/bin/python -c 'import flask, google.auth, sqlalchemy'" "source venv/bin/activate && pip install -r requirements.txt"; then
        passed_count=$((passed_count + 1))
    else
        all_passed=false
    fi
    
    # Step 9: Check .env file
    step_count=$((step_count + 1))
    if check_step "Environment File" "[ -f '.env' ]" "Create .env file with required variables"; then
        passed_count=$((passed_count + 1))
    else
        all_passed=false
    fi
    
    # Step 10: Check .env content
    step_count=$((step_count + 1))
    if check_step "Environment Variables" "grep -q 'SECRET_KEY' .env && grep -q 'WHITELIST_TOKEN' .env" "Add SECRET_KEY and WHITELIST_TOKEN to .env"; then
        passed_count=$((passed_count + 1))
    else
        all_passed=false
    fi
    
    # Step 11: Check database file
    step_count=$((step_count + 1))
    if check_step "Database File" "[ -f 'gbot.db' ]" "Initialize database with: python3 -c \"from app import app, db; app.app_context().push(); db.create_all()\""; then
        passed_count=$((passed_count + 1))
    else
        all_passed=false
    fi
    
    # Step 12: Check database tables
    step_count=$((step_count + 1))
    if check_step "Database Tables" "sqlite3 gbot.db '.tables' | grep -q 'user'" "Initialize database tables"; then
        passed_count=$((passed_count + 1))
    else
        all_passed=false
    fi
    
    # Step 13: Check if app can import
    step_count=$((step_count + 1))
    if check_step "Application Import" "venv/bin/python -c 'import app'" "Check for syntax errors in app.py"; then
        passed_count=$((passed_count + 1))
    else
        all_passed=false
    fi
    
    # Step 14: Check if app can start (without running)
    step_count=$((step_count + 1))
    if check_step "Application Startup" "venv/bin/python -c 'from app import app; print(\"App loaded successfully\")'" "Fix any import or configuration errors"; then
        passed_count=$((passed_count + 1))
    else
        all_passed=false
    fi
    
    # Step 15: Check file permissions
    step_count=$((step_count + 1))
    if check_step "File Permissions" "[ -r 'app.py' ] && [ -x 'install.py' ]" "chmod +x *.py *.sh"; then
        passed_count=$((passed_count + 1))
    else
        all_passed=false
    fi
    
    # Summary
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}                    Checklist Summary                        ${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "Total Steps: ${BLUE}$step_count${NC}"
    echo -e "Passed: ${GREEN}$passed_count${NC}"
    echo -e "Failed: ${RED}$((step_count - passed_count))${NC}"
    echo ""
    
    if [ "$all_passed" = true ]; then
        echo -e "${GREEN}🎉 All checks passed! Your installation is ready.${NC}"
        echo ""
        echo -e "Next steps:"
        echo -e "  1. Activate virtual environment: ${BLUE}source venv/bin/activate${NC}"
        echo -e "  2. Start the application: ${BLUE}python3 app.py${NC}"
        echo -e "  3. Access at: ${BLUE}http://localhost:5000${NC}"
        echo -e "  4. Login with: ${BLUE}admin${NC} / ${BLUE}A9B3nX#Q8k$mZ6vw${NC}"
    else
        echo -e "${YELLOW}⚠️  Some checks failed. Please fix the issues above before proceeding.${NC}"
        echo ""
        echo -e "Common fixes:"
        echo -e "  • Run: ${BLUE}./setup_enhanced.sh --install${NC}"
        echo -e "  • Or: ${BLUE}python3 install.py${NC}"
        echo -e "  • Check logs: ${BLUE}cat install.log${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
}

# Run the checklist
run_installation_checklist
