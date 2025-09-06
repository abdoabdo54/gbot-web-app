import os
from datetime import datetime
import json
import logging
import random
import string
import csv
import io
import smtplib
import tempfile
from werkzeug.security import generate_password_hash, check_password_hash
import logging.handlers

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from google_auth_oauthlib.flow import InstalledAppFlow
from faker import Faker
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from core_logic import google_api
from database import db, User, WhitelistedIP, UsedDomain, GoogleAccount, GoogleToken, Scope

app = Flask(__name__)
app.config.from_object('config')

# Set secret key for sessions
if app.config.get('SECRET_KEY'):
    app.secret_key = app.config['SECRET_KEY']
else:
    app.secret_key = 'fallback-secret-key-for-development'

# Configure session settings
app.config['SESSION_COOKIE_SECURE'] = False  # Allow HTTP
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

db.init_app(app)

# Production logging configuration
if not app.debug:
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Configure file handler for production
    file_handler = logging.handlers.RotatingFileHandler(
        'logs/gbot.log', maxBytes=10240000, backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    
    app.logger.setLevel(logging.INFO)
    app.logger.info('GBot startup')

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', password=generate_password_hash('A9B3nX#Q8k$mZ6vw', method='pbkdf2:sha256'), role='admin')
        db.session.add(admin_user)
        db.session.commit()

def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.before_request
def before_request():
    # Debug logging
    app.logger.debug(f"Before request: endpoint={request.endpoint}, user={session.get('user')}, emergency_access={session.get('emergency_access')}, client_ip={get_client_ip()}")
    
    # Always allow these routes without any checks (whitelisted routes)
    if request.endpoint in ['static', 'login', 'emergency_access', 'test-admin']:
        app.logger.debug(f"Allowing {request.endpoint} route without restrictions")
        return

    # Allow emergency access users to access all endpoints
    if session.get('emergency_access'):
        app.logger.debug(f"Allowing emergency access user to access {request.endpoint}")
        return

    # IP Whitelist check - for ALL users (including logged-in users)
    # Check if IP whitelist is enabled
    if app.config.get('ENABLE_IP_WHITELIST', True):  # Default to True for security
        client_ip = get_client_ip()
        app.logger.info(f"Checking IP whitelist for {client_ip} accessing {request.endpoint}")
        
        # Check if IP is whitelisted
        whitelisted_ip = WhitelistedIP.query.filter_by(ip_address=client_ip).first()
        
        if not whitelisted_ip:
            app.logger.warning(f"IP {client_ip} not whitelisted, access denied to {request.endpoint}")
            return f"Access denied. IP {client_ip} is not whitelisted. Please contact administrator or use emergency access.", 403
        else:
            app.logger.info(f"IP {client_ip} is whitelisted, allowing access")
    else:
        app.logger.debug("IP whitelist disabled, allowing access")

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Debug logging
        app.logger.info(f"Login attempt for username: {username}")
        
        user = User.query.filter_by(username=username).first()
        
        if user:
            app.logger.info(f"User found: {user.username}, role: {user.role}")
            if check_password_hash(user.password, password):
                app.logger.info(f"Password verified for user: {username}")
                session['user'] = user.username
                session['role'] = user.role
                session.permanent = True  # Make session persistent
                app.logger.info(f"Session set - user: {session.get('user')}, role: {session.get('role')}")
                flash(f'Welcome {user.username}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                app.logger.warning(f"Invalid password for user: {username}")
                flash('Invalid credentials', 'error')
        else:
            app.logger.warning(f"User not found: {username}")
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/test-admin')
def test_admin():
    """Test route to check admin user and authentication"""
    try:
        admin_user = User.query.filter_by(username='admin').first()
        if admin_user:
            from werkzeug.security import check_password_hash
            password_works = check_password_hash(admin_user.password, 'A9B3nX#Q8k$mZ6vw')
            return jsonify({
                'admin_exists': True,
                'username': admin_user.username,
                'role': admin_user.role,
                'password_works': password_works,
                'session_user': session.get('user'),
                'session_role': session.get('role')
            })
        else:
            return jsonify({'admin_exists': False})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/whitelist-bypass')
def whitelist_bypass():
    """Temporary bypass route for whitelist management"""
    # Set emergency access session
    session['emergency_access'] = True
    session['role'] = 'admin'
    session['user'] = 'emergency_admin'
    session.permanent = True
    
    flash('Emergency access granted for whitelist management', 'success')
    return redirect(url_for('whitelist'))

@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Test database connection
        db.session.execute('SELECT 1')
        db_status = 'healthy'
    except Exception as e:
        db_status = f'unhealthy: {str(e)}'
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'database': db_status,
        'version': '1.0.0'
    })

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    accounts = GoogleAccount.query.all()
    return render_template('dashboard.html', accounts=accounts, user=session.get('user'), role=session.get('role'))

@app.route('/users')
@login_required
def users():
    if session.get('role') != 'admin':
        flash("Admin access required.", "danger")
        return redirect(url_for('dashboard'))
    return render_template('users.html', user=session.get('user'), role=session.get('role'))

@app.route('/emergency_access')
def emergency_access():
    """Emergency access route that bypasses IP whitelist for initial setup"""
    # Check for static key in URL parameters
    static_key = request.args.get('key', '')
    whitelist_token = app.config.get('WHITELIST_TOKEN', '')
    secret_key = app.config.get('SECRET_KEY', '')
    
    # Debug logging
    app.logger.info(f"Emergency access route - Key provided: {static_key[:8] if static_key else 'None'}..., WHITELIST_TOKEN: {whitelist_token[:8] if whitelist_token else 'None'}..., SECRET_KEY: {secret_key[:8] if secret_key else 'None'}...")
    
    # If WHITELIST_TOKEN is provided directly, auto-whitelist the current IP
    if static_key == whitelist_token:
        client_ip = get_client_ip()
        app.logger.info(f"WHITELIST_TOKEN provided - auto-whitelisting IP: {client_ip}")
        
        # Check if IP already exists
        existing_ip = WhitelistedIP.query.filter_by(ip_address=client_ip).first()
        if not existing_ip:
            new_ip = WhitelistedIP(ip_address=client_ip)
            db.session.add(new_ip)
            db.session.commit()
            app.logger.info(f"IP {client_ip} auto-whitelisted successfully")
            flash(f'IP {client_ip} has been automatically whitelisted!', 'success')
        else:
            app.logger.info(f"IP {client_ip} already whitelisted")
            flash(f'IP {client_ip} is already whitelisted!', 'info')
        
        # Set session and redirect to whitelist management
        session['emergency_access'] = True
        session['role'] = 'admin'
        session['user'] = 'emergency_admin'
        return redirect(url_for('whitelist'))
    
    # If SECRET_KEY is provided, show the emergency access form
    elif static_key == secret_key:
        app.logger.info("SECRET_KEY provided - showing emergency access form")
        return render_template('emergency_access.html')
    
    # If no valid key, show the emergency access form
    else:
        app.logger.info("No valid key provided - showing emergency access form")
        return render_template('emergency_access.html')

@app.route('/api/emergency-add-ip', methods=['POST'])
def api_emergency_add_ip():
    """Emergency API to add IP to whitelist without authentication"""
    try:
        data = request.get_json()
        ip_address = data.get('ip_address', '').strip()
        emergency_key = data.get('emergency_key', '').strip()
        
        # Debug logging
        app.logger.info(f"Emergency access attempt - IP: {ip_address}, Key provided: {emergency_key[:8]}...")
        
        if not ip_address:
            return jsonify({'success': False, 'error': 'IP address required'})
        
        if not emergency_key:
            return jsonify({'success': False, 'error': 'Emergency key required'})
        
        # Check against both WHITELIST_TOKEN and SECRET_KEY
        whitelist_token = app.config.get('WHITELIST_TOKEN', '')
        secret_key = app.config.get('SECRET_KEY', '')
        
        if not whitelist_token and not secret_key:
            return jsonify({'success': False, 'error': 'No emergency keys configured'})
        
        # Accept either key
        if emergency_key != whitelist_token and emergency_key != secret_key:
            return jsonify({'success': False, 'error': 'Invalid emergency key. Please use your WHITELIST_TOKEN or SECRET_KEY.'})
        
        # Check if IP already exists
        existing_ip = WhitelistedIP.query.filter_by(ip_address=ip_address).first()
        if existing_ip:
            app.logger.info(f"IP {ip_address} already exists in whitelist")
            return jsonify({'success': True, 'message': f'IP address {ip_address} is already whitelisted'})
        
        # Add new IP to whitelist
        new_ip = WhitelistedIP(ip_address=ip_address)
        db.session.add(new_ip)
        db.session.commit()
        
        app.logger.info(f"IP {ip_address} successfully whitelisted via emergency access")
        
        # Set session for this user so they can access other pages
        session['emergency_access'] = True
        session['role'] = 'admin'
        session['user'] = 'emergency_admin'
        
        return jsonify({'success': True, 'message': f'IP address {ip_address} whitelisted successfully'})
        
    except Exception as e:
        app.logger.error(f"Emergency access error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/debug-config')
def api_debug_config():
    """Debug endpoint to check configuration values"""
    return jsonify({
        'WHITELIST_TOKEN': app.config.get('WHITELIST_TOKEN', '')[:8] + '...' if app.config.get('WHITELIST_TOKEN') else 'None',
        'SECRET_KEY': app.config.get('SECRET_KEY', '')[:8] + '...' if app.config.get('SECRET_KEY') else 'None',
        'ENABLE_IP_WHITELIST': app.config.get('ENABLE_IP_WHITELIST', False),
        'DEBUG': app.config.get('DEBUG', False),
        'note': 'Both WHITELIST_TOKEN and SECRET_KEY can be used for emergency access'
    })

@app.route('/api/debug-session')
def api_debug_session():
    """Debug endpoint to check current session state"""
    return jsonify({
        'session_data': dict(session),
        'client_ip': get_client_ip(),
        'endpoint': request.endpoint if request.endpoint else 'None'
    })

@app.route('/api/debug-whitelist')
def api_debug_whitelist():
    """Debug endpoint to check whitelist status"""
    try:
        client_ip = get_client_ip()
        whitelisted_ips = WhitelistedIP.query.all()
        ip_list = [ip.ip_address for ip in whitelisted_ips]
        
        return jsonify({
            'client_ip': client_ip,
            'whitelisted_ips': ip_list,
            'is_whitelisted': client_ip in ip_list,
            'total_whitelisted': len(ip_list),
            'enable_ip_whitelist_config': app.config.get('ENABLE_IP_WHITELIST', False),
            'app_debug_mode': app.debug,
            'emergency_access_session': session.get('emergency_access', False),
            'session_data': {
                'user': session.get('user'),
                'role': session.get('role'),
                'emergency_access': session.get('emergency_access')
            }
        })
    except Exception as e:
        app.logger.error(f"Error in debug-whitelist endpoint: {str(e)}")
        return jsonify({'error': str(e)})

@app.route('/whitelist')
def whitelist():
    """Whitelist management page - accessible via emergency access or admin login"""
    # Check if user has emergency access or is logged in as admin
    if not session.get('emergency_access') and not session.get('user'):
        flash("Access denied. Please use emergency access or log in.", "danger")
        return redirect(url_for('login'))
    
    if session.get('role') != 'admin' and not session.get('emergency_access'):
        flash("Admin access required.", "danger")
        return redirect(url_for('dashboard'))
    
    # Get all whitelisted IPs for display
    try:
        whitelisted_ips = WhitelistedIP.query.all()
        ip_list = [ip.ip_address for ip in whitelisted_ips]
    except Exception as e:
        app.logger.error(f"Error fetching whitelisted IPs: {e}")
        ip_list = []
    
    app.logger.info(f"Whitelist access granted: user={session.get('user')}, role={session.get('role')}, emergency_access={session.get('emergency_access')}")
    return render_template('whitelist.html', user=session.get('user'), role=session.get('role'), whitelisted_ips=ip_list)

@app.route('/api/add-user', methods=['POST'])
@login_required
def api_add_user():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        role = data.get('role', 'support')
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'})
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': 'Username already exists'})
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'User {username} created successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/list-users', methods=['GET'])
@login_required
def api_list_users():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    try:
        users = User.query.all()
        user_list = [{'username': user.username, 'role': user.role} for user in users]
        return jsonify({'success': True, 'users': user_list})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/edit-user', methods=['POST'])
@login_required
def api_edit_user():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        new_password = data.get('password', '').strip()
        new_role = data.get('role', '').strip()
        
        if not username:
            return jsonify({'success': False, 'error': 'Username required'})
        
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'success': False, 'error': 'User not found'})
        
        if not new_password:
            return jsonify({'success': False, 'error': 'Password required'})
        
        if new_role not in ['admin', 'support', 'mailer']:
            return jsonify({'success': False, 'error': 'Role must be admin, support, or mailer'})
        
        user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        user.role = new_role
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'User {username} updated successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/delete-user', methods=['POST'])
@login_required
def api_delete_user():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        
        if not username:
            return jsonify({'success': False, 'error': 'Username required'})
        
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'success': False, 'error': 'User not found'})
        
        if username == session.get('user'):
            return jsonify({'success': False, 'error': 'Cannot delete your own account'})
        
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'User {username} deleted successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/add-whitelist-ip', methods=['POST'])
@login_required
def api_add_whitelist_ip():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    try:
        data = request.get_json()
        ip_address = data.get('ip_address', '').strip()
        
        if not ip_address:
            return jsonify({'success': False, 'error': 'IP address required'})
        
        if WhitelistedIP.query.filter_by(ip_address=ip_address).first():
            return jsonify({'success': False, 'error': 'IP address already exists'})
        
        new_ip = WhitelistedIP(ip_address=ip_address)
        db.session.add(new_ip)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'IP address {ip_address} whitelisted successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/list-whitelist-ips', methods=['GET'])
@login_required
def api_list_whitelist_ips():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    try:
        ips = WhitelistedIP.query.all()
        ip_list = [ip.ip_address for ip in ips]
        return jsonify({'success': True, 'ips': ip_list})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/delete-whitelist-ip', methods=['POST'])
def api_delete_whitelist_ip():
    """Delete IP from whitelist - accessible via emergency access or admin login"""
    # Check if user has emergency access or is logged in as admin
    if not session.get('emergency_access') and not session.get('user'):
        return jsonify({'success': False, 'error': 'Access denied. Please use emergency access or log in.'})
    
    if session.get('role') != 'admin' and not session.get('emergency_access'):
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    try:
        data = request.get_json()
        ip_address = data.get('ip_address', '').strip()
        
        if not ip_address:
            return jsonify({'success': False, 'error': 'IP address required'})
        
        ip_to_delete = WhitelistedIP.query.filter_by(ip_address=ip_address).first()
        if not ip_to_delete:
            return jsonify({'success': False, 'error': 'IP address not found'})
        
        db.session.delete(ip_to_delete)
        db.session.commit()
        
        app.logger.info(f"IP {ip_address} deleted from whitelist by user: {session.get('user', 'emergency_access')}")
        return jsonify({'success': True, 'message': f'IP address {ip_address} removed from whitelist'})
        
    except Exception as e:
        app.logger.error(f"Error deleting IP from whitelist: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/authenticate', methods=['POST'])
@login_required
def api_authenticate():
    try:
        data = request.get_json()
        account_name = data.get('account_name')
        account_id = data.get('account_id')
        
        if not account_name and not account_id:
            return jsonify({'success': False, 'error': 'No account specified'})
        
        # Try to find account by ID first (more reliable), then by name
        if account_id:
            account = GoogleAccount.query.get(account_id)
        else:
            account = GoogleAccount.query.filter_by(account_name=account_name).first()
            
        if not account:
            return jsonify({'success': False, 'error': 'Account not found in database'})
        
        # Use the account name from the database record
        account_name = account.account_name
        
        service_key = google_api._get_session_key(account_name)
        if service_key in session and session.get(service_key):
            session['current_account_name'] = account_name
            return jsonify({
                'success': True, 
                'message': f'Already authenticated for {account_name} in this session'
            })
        
        if google_api.is_token_valid(account_name):
            success = google_api.authenticate_with_tokens(account_name)
            if success:
                # Set the current account in session for persistence
                session['current_account_name'] = account_name
                return jsonify({
                    'success': True, 
                    'message': f'Authenticated using cached tokens for {account_name}'
                })
        
        oauth_url = google_api.get_oauth_url(account_name, {'client_id': account.client_id, 'client_secret': account.client_secret})
        if oauth_url:
            return jsonify({
                'success': False,
                'oauth_required': True,
                'oauth_url': oauth_url,
                'message': 'Please complete OAuth authentication'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to generate OAuth URL'})
            
    except Exception as e:
        logging.error(f"Authentication error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/add-account', methods=['POST'])
@login_required
def api_add_account():
    # Check if user is mailer role (not allowed to add accounts)
    if session.get('role') == 'mailer':
        return jsonify({'success': False, 'error': 'Mailer users cannot add accounts'})
    
    try:
        data = request.get_json()
        account_name = data.get('account_name')
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        
        if not all([account_name, client_id, client_secret]):
            return jsonify({'success': False, 'error': 'All fields are required'})
        
        if '@' not in account_name:
            return jsonify({'success': False, 'error': 'Invalid email format'})
        
        if GoogleAccount.query.filter_by(account_name=account_name).first():
            return jsonify({'success': False, 'error': 'Account already exists'})

        new_account = GoogleAccount(account_name=account_name, client_id=client_id, client_secret=client_secret)
        db.session.add(new_account)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'Account {account_name} added successfully'})
            
    except Exception as e:
        logging.error(f"Add account error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/list-accounts', methods=['GET'])
@login_required
def api_list_accounts():
    """List all Google accounts from database"""
    try:
        accounts = GoogleAccount.query.all()
        account_list = []
        for account in accounts:
            # Check if account has valid tokens
            token = GoogleToken.query.filter_by(account_id=account.id).first()
            is_authenticated = token is not None and token.token is not None
            
            account_data = {
                'id': account.id,
                'account_name': account.account_name,
                'client_id': account.client_id,
                'client_secret': account.client_secret,
                'is_authenticated': is_authenticated,
                'has_tokens': token is not None
            }
            account_list.append(account_data)
        
        return jsonify({'success': True, 'accounts': account_list})
    except Exception as e:
        logging.error(f"List accounts error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/delete-account', methods=['POST'])
@login_required
def api_delete_account():
    """Delete a Google account from database"""
    try:
        data = request.get_json()
        account_id = data.get('account_id')
        
        if not account_id:
            return jsonify({'success': False, 'error': 'Account ID required'})
        
        account = GoogleAccount.query.get(account_id)
        if not account:
            return jsonify({'success': False, 'error': 'Account not found'})
        
        # Delete associated tokens first
        GoogleToken.query.filter_by(account_id=account_id).delete()
        
        # Delete the account
        db.session.delete(account)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'Account {account.account_name} deleted successfully'})
    except Exception as e:
        logging.error(f"Delete account error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/get-account-status', methods=['GET'])
@login_required
def api_get_account_status():
    """Get authentication status for all accounts"""
    try:
        accounts = GoogleAccount.query.all()
        total_accounts = len(accounts)
        authenticated_count = 0
        need_auth_count = 0
        
        for account in accounts:
            token = GoogleToken.query.filter_by(account_id=account.id).first()
            if token and token.token:
                authenticated_count += 1
            else:
                need_auth_count += 1
        
        status = {
            'total': total_accounts,
            'authenticated': authenticated_count,
            'need_auth': need_auth_count,
            'status': 'Complete'
        }
        
        return jsonify({'success': True, 'status': status})
    except Exception as e:
        logging.error(f"Get account status error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/add-accounts-from-json', methods=['POST'])
@login_required
def api_add_accounts_from_json():
    """Add multiple accounts from JSON data (for backward compatibility)"""
    try:
        data = request.get_json()
        accounts_data = data.get('accounts', [])
        
        if not accounts_data:
            return jsonify({'success': False, 'error': 'No accounts data provided'})
        
        added_count = 0
        errors = []
        
        for account_data in accounts_data:
            try:
                account_name = account_data.get('account_name')
                client_id = account_data.get('client_id')
                client_secret = account_data.get('client_secret')
                
                if not all([account_name, client_id, client_secret]):
                    errors.append(f"Missing data for account: {account_name}")
                    continue
                
                # Check if account already exists
                if GoogleAccount.query.filter_by(account_name=account_name).first():
                    errors.append(f"Account {account_name} already exists")
                    continue
                
                # Create new account
                new_account = GoogleAccount(
                    account_name=account_name,
                    client_id=client_id,
                    client_secret=client_secret
                )
                db.session.add(new_account)
                added_count += 1
                
            except Exception as e:
                errors.append(f"Error processing account {account_name}: {str(e)}")
        
        # Commit all changes
        db.session.commit()
        
        result = {
            'success': True,
            'message': f'Added {added_count} accounts successfully',
            'added_count': added_count,
            'errors': errors
        }
        
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"Add accounts from JSON error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/check-token-status', methods=['GET'])
@login_required
def api_check_token_status():
    """Check token status for all accounts"""
    try:
        accounts = GoogleAccount.query.all()
        token_status = []
        
        for account in accounts:
            token = GoogleToken.query.filter_by(account_id=account.id).first()
            
            status_info = {
                'account_id': account.id,
                'account_name': account.account_name,
                'has_tokens': token is not None,
                'token_valid': False,
                'needs_auth': True
            }
            
            if token and token.token:
                # Basic token validation (you can enhance this)
                status_info['token_valid'] = True
                status_info['needs_auth'] = False
            
            token_status.append(status_info)
        
        return jsonify({'success': True, 'token_status': token_status})
        
    except Exception as e:
        logging.error(f"Check token status error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/oauth-callback')
def oauth_callback():
    try:
        code = request.args.get('code')
        
        if not code:
            return "❌ No authorization code received", 400
        
        return f"""
        <html>
        <head><title>✅ Authentication Code Ready</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5;">
            <div style="background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: 0 auto; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h2 style="color: #28a745;">✅ Authentication Successful!</h2>
                <p style="font-size: 18px; margin: 20px 0;">Copy this authorization code:</p>
                
                <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; border: 2px dashed #28a745; margin: 20px 0;">
                    <input type="text" value="{code}" readonly onclick="this.select()" 
                           style="width: 100%; padding: 10px; font-family: monospace; font-size: 14px; border: none; background: transparent; text-align: center;">
                </div>
                
                <p style="color: #666; margin: 20px 0;"><strong>Next Steps:</strong></p>
                <ol style="text-align: left; max-width: 400px; margin: 0 auto; color: #666;">
                    <li>Click in the box above to select the code</li>
                    <li>Copy it (Ctrl+C or Cmd+C)</li>
                    <li>Return to your main app browser</li>
                    <li>Paste the code to complete authentication</li>
                </ol>
                
                <div style="margin-top: 30px;">
                    <button onclick="copyCode()" style="background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 5px; font-size: 16px; cursor: pointer;">
                        📋 Copy Code
                    </button>
                </div>
            </div>
            
            <script>
                function copyCode() {{
                    const input = document.querySelector('input');
                    input.select();
                    document.execCommand('copy');
                    alert('✅ Code copied to clipboard!');
                }}
            </script>
        </body>
        </html>
        """
        
    except Exception as e:
        return f"❌ Error: {str(e)}", 500

@app.route('/api/complete-oauth', methods=['POST'])
@login_required
def api_complete_oauth():
    try:
        data = request.get_json()
        auth_code = data.get('auth_code')
        account_name = data.get('account_name')
        
        if not auth_code or not account_name:
            return jsonify({'success': False, 'error': 'Code and account name required'})
        
        account = GoogleAccount.query.filter_by(account_name=account_name).first()
        if not account:
            return jsonify({'success': False, 'error': 'Account not found'})
        
        creds_data = {'client_id': account.client_id, 'client_secret': account.client_secret}
        
        flow_config = {
            "installed": {
                "client_id": creds_data['client_id'],
                "project_id": "gbot-project",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_secret": creds_data['client_secret'],
                "redirect_uris": ["https://g-workspace.ecochain.site/oauth-callback"]
            }
        }
        
        flow = InstalledAppFlow.from_client_config(flow_config, app.config['SCOPES'])
        flow.redirect_uri = "https://g-workspace.ecochain.site/oauth-callback"
        
        flow.fetch_token(code=auth_code)
        credentials = flow.credentials
        
        token = GoogleToken.query.filter_by(account_id=account.id).first()
        if not token:
            token = GoogleToken(account_id=account.id)

        token.token = credentials.token
        token.refresh_token = credentials.refresh_token
        token.token_uri = credentials.token_uri
        
        # Clear existing scopes and add new ones
        token.scopes.clear()
        for scope_name in credentials.scopes:
            scope = Scope.query.filter_by(name=scope_name).first()
            if not scope:
                scope = Scope(name=scope_name)
                db.session.add(scope)
            token.scopes.append(scope)

        db.session.add(token)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'Authentication completed for {account_name}'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/create-gsuite-user', methods=['POST'])
@login_required
def api_create_gsuite_user():
    try:
        data = request.get_json()
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        password = data.get('password')

        if not all([first_name, last_name, email, password]):
            return jsonify({'success': False, 'error': 'All fields are required'})

        result = google_api.create_gsuite_user(first_name, last_name, email, password)
        return jsonify(result)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/get-domain-info', methods=['GET'])
@login_required
def api_get_domain_info():
    try:
        result = google_api.get_domain_info()
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/add-domain-alias', methods=['POST'])
@login_required
def api_add_domain_alias():
    try:
        data = request.get_json()
        domain_alias = data.get('domain_alias')

        if not domain_alias:
            return jsonify({'success': False, 'error': 'Domain alias is required'})

        result = google_api.add_domain_alias(domain_alias)
        return jsonify(result)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/delete-domain', methods=['POST'])
@login_required
def api_delete_domain():
    try:
        data = request.get_json()
        domain_name = data.get('domain_name')

        if not domain_name:
            return jsonify({'success': False, 'error': 'Domain name is required'})

        result = google_api.delete_domain(domain_name)
        return jsonify(result)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/retrieve-users', methods=['POST'])
@login_required
def api_retrieve_users():
    """Retrieve all users from the authenticated Google account"""
    try:
        # Check if user is authenticated
        if 'current_account_name' not in session:
            return jsonify({'success': False, 'error': 'No account authenticated. Please authenticate first.'})
        
        # Get the current authenticated account
        account_name = session.get('current_account_name')
        
        # First, try to authenticate using saved tokens if service is not available
        if not google_api.service:
            # Check if we have valid tokens for this account
            if google_api.is_token_valid(account_name):
                success = google_api.authenticate_with_tokens(account_name)
                if not success:
                    return jsonify({'success': False, 'error': 'Failed to authenticate with saved tokens. Please re-authenticate.'})
            else:
                return jsonify({'success': False, 'error': 'No valid tokens found. Please re-authenticate.'})
        
        # Now try to retrieve users
        try:
            # Use the google_api method to retrieve users
            result = google_api.get_users(max_results=500)
            
            if not result['success']:
                return jsonify({'success': False, 'error': result['error']})
            
            users = result['users']
            
            # Format user data
            formatted_users = []
            for user in users:
                user_data = {
                    'email': user.get('primaryEmail', ''),
                    'first_name': user.get('name', {}).get('givenName', ''),
                    'last_name': user.get('name', {}).get('familyName', ''),
                    'admin': user.get('isAdmin', False),
                    'suspended': user.get('suspended', False)
                }
                formatted_users.append(user_data)
            
            return jsonify({
                'success': True,
                'users': formatted_users,
                'total_count': len(formatted_users)
            })
            
        except Exception as api_error:
            logging.error(f"Google API error: {api_error}")
            return jsonify({'success': False, 'error': f'Failed to retrieve users: {str(api_error)}'})
            
    except Exception as e:
        logging.error(f"Retrieve users error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/update-all-passwords', methods=['POST'])
@login_required
def api_update_all_passwords():
    """Update passwords for multiple users"""
    try:
        data = request.get_json()
        password = data.get('password')
        user_emails = data.get('user_emails', [])
        
        if not password or len(password) < 8:
            return jsonify({'success': False, 'error': 'Password must be at least 8 characters'})
        
        if not user_emails:
            return jsonify({'success': False, 'error': 'No user emails provided'})
        
        # Check if user is authenticated
        if 'current_account_name' not in session:
            return jsonify({'success': False, 'error': 'No account authenticated. Please authenticate first.'})
        
        # Get the current authenticated account
        account_name = session.get('current_account_name')
        
        # First, try to authenticate using saved tokens if service is not available
        if not google_api.service:
            # Check if we have valid tokens for this account
            if google_api.is_token_valid(account_name):
                success = google_api.authenticate_with_tokens(account_name)
                if not success:
                    return jsonify({'success': False, 'error': 'Failed to authenticate with saved tokens. Please re-authenticate.'})
            else:
                return jsonify({'success': False, 'error': 'No valid tokens found. Please re-authenticate.'})
        
        successful_emails = []
        failed_details = []
        
        for email in user_emails:
            try:
                # Update user password in Google Admin Directory API
                user_body = {
                    'password': password,
                    'changePasswordAtNextLogin': False
                }
                
                google_api.service.users().update(userKey=email, body=user_body).execute()
                successful_emails.append(email)
                
            except Exception as user_error:
                failed_details.append({
                    'email': email,
                    'error': str(user_error)
                })
        
        return jsonify({
            'success': True,
            'message': f'Password update completed. {len(successful_emails)} successful, {len(failed_details)} failed.',
            'successful_emails': successful_emails,
            'failed_details': failed_details
        })
        
    except Exception as e:
        logging.error(f"Update all passwords error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/retrieve-domains', methods=['POST'])
@login_required
def api_retrieve_domains():
    """Retrieve all domains from the authenticated Google account"""
    try:
        # Check if user is authenticated
        if 'current_account_name' not in session:
            return jsonify({'success': False, 'error': 'No account authenticated. Please authenticate first.'})
        
        # Get the current authenticated account
        account_name = session.get('current_account_name')
        
        # First, try to authenticate using saved tokens if service is not available
        if not google_api.service:
            # Check if we have valid tokens for this account
            if google_api.is_token_valid(account_name):
                success = google_api.authenticate_with_tokens(account_name)
                if not success:
                    return jsonify({'success': False, 'error': 'Failed to authenticate with saved tokens. Please re-authenticate.'})
            else:
                return jsonify({'success': False, 'error': 'No valid tokens found. Please re-authenticate.'})
        
        try:
            # Use the existing get_domain_info method
            result = google_api.get_domain_info()
            
            if not result['success']:
                return jsonify({'success': False, 'error': result['error']})
            
            domains = result['domains']
            
            # Get all users to calculate domain usage (handle pagination for large user bases)
            all_users = []
            page_token = None
            
            while True:
                try:
                    if page_token:
                        users_result = google_api.service.users().list(
                            customer='my_customer',
                            maxResults=500,
                            pageToken=page_token
                        ).execute()
                    else:
                        users_result = google_api.service.users().list(
                            customer='my_customer',
                            maxResults=500
                        ).execute()
                    
                    users = users_result.get('users', [])
                    all_users.extend(users)
                    
                    page_token = users_result.get('nextPageToken')
                    if not page_token:
                        break
                        
                except Exception as e:
                    logging.warning(f"Failed to retrieve users page: {e}")
                    break
            
            logging.info(f"Retrieved {len(all_users)} total users for domain calculation")
            
            # Calculate user count per domain
            domain_user_counts = {}
            for user in users:
                email = user.get('primaryEmail', '')
                if email and '@' in email:
                    domain = email.split('@')[1]
                    domain_user_counts[domain] = domain_user_counts.get(domain, 0) + 1
            
            # Format domain data with actual user counts and usage status
            formatted_domains = []
            for domain in domains:
                domain_name = domain.get('domainName', '')
                user_count = domain_user_counts.get(domain_name, 0)
                is_used = user_count > 0
                
                domain_data = {
                    'domain_name': domain_name,
                    'verified': domain.get('verified', False),
                    'user_count': user_count,
                    'is_used': is_used
                }
                formatted_domains.append(domain_data)
                
                # Sync domain usage data to database
                try:
                    from database import UsedDomain
                    existing_domain = UsedDomain.query.filter_by(domain_name=domain_name).first()
                    if existing_domain:
                        existing_domain.user_count = user_count
                        existing_domain.is_verified = domain.get('verified', False)
                        existing_domain.updated_at = db.func.current_timestamp()
                    else:
                        new_domain = UsedDomain(
                            domain_name=domain_name,
                            user_count=user_count,
                            is_verified=domain.get('verified', False)
                        )
                        db.session.add(new_domain)
                    
                    db.session.commit()
                    logging.debug(f"Synced domain {domain_name} to database: {user_count} users, verified: {domain.get('verified', False)}")
                except Exception as db_error:
                    logging.warning(f"Failed to sync domain {domain_name} to database: {db_error}")
                    # Try to rollback the session
                    try:
                        db.session.rollback()
                    except:
                        pass
            
            return jsonify({
                'success': True,
                'domains': formatted_domains
            })
            
        except Exception as api_error:
            logging.error(f"Google API error: {api_error}")
            return jsonify({'success': False, 'error': f'Failed to retrieve domains: {str(api_error)}'})
            
    except Exception as e:
        logging.error(f"Retrieve domains error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/get-domain-usage-stats', methods=['GET'])
@login_required
def api_get_domain_usage_stats():
    """Get domain usage statistics from database"""
    try:
        from database import UsedDomain
        domains = UsedDomain.query.all()
        
        # Sort domains by user count (descending) and then by name
        sorted_domains = sorted(domains, key=lambda x: (x.user_count, x.domain_name), reverse=True)
        
        stats = {
            'total_domains': len(domains),
            'used_domains': len([d for d in domains if d.user_count > 0]),
            'available_domains': len([d for d in domains if d.user_count == 0]),
            'total_users': sum(d.user_count for d in domains),
            'domains': [
                {
                    'domain_name': d.domain_name,
                    'user_count': d.user_count,
                    'is_verified': d.is_verified,
                    'is_used': d.user_count > 0,
                    'last_updated': d.updated_at.isoformat() if d.updated_at else None
                }
                for d in sorted_domains
            ]
        }
        
        logging.info(f"Domain usage stats: {stats['total_domains']} domains, {stats['total_users']} users")
        
        return jsonify({'success': True, 'stats': stats})
        
    except Exception as e:
        logging.error(f"Get domain usage stats error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/clear-old-domain-data', methods=['POST'])
@login_required
def api_clear_old_domain_data():
    """Clear old domain data from database"""
    try:
        from database import UsedDomain
        
        # Delete domains that haven't been updated in the last 30 days
        from datetime import datetime, timedelta
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        
        old_domains = UsedDomain.query.filter(UsedDomain.updated_at < cutoff_date).all()
        count = len(old_domains)
        
        for domain in old_domains:
            db.session.delete(domain)
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Cleared {count} old domain records',
            'cleared_count': count
        })
        
    except Exception as e:
        logging.error(f"Clear old domain data error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/load-suspended-users', methods=['POST'])
@login_required
def api_load_suspended_users():
    """Load suspended users from the authenticated Google account"""
    try:
        # Check if user is authenticated
        if 'current_account_name' not in session:
            return jsonify({'success': False, 'error': 'No account authenticated. Please authenticate first.'})
        
        # Get the current authenticated account
        account_name = session.get('current_account_name')
        
        # First, try to authenticate using saved tokens if service is not available
        if not google_api.service:
            # Check if we have valid tokens for this account
            if google_api.is_token_valid(account_name):
                success = google_api.authenticate_with_tokens(account_name)
                if not success:
                    return jsonify({'success': False, 'error': 'Failed to authenticate with saved tokens. Please re-authenticate.'})
            else:
                return jsonify({'success': False, 'error': 'No valid tokens found. Please re-authenticate.'})
        
        try:
            # Retrieve suspended users from Google Admin Directory API
            users_result = google_api.service.users().list(
                customer='my_customer', 
                query='suspended:true',
                maxResults=500
            ).execute()
            
            suspended_users = users_result.get('users', [])
            
            # Format suspended user data with full information
            formatted_suspended_users = []
            for user in suspended_users:
                if user.get('primaryEmail'):
                    user_data = {
                        'email': user.get('primaryEmail', ''),
                        'first_name': user.get('name', {}).get('givenName', ''),
                        'last_name': user.get('name', {}).get('familyName', ''),
                        'admin': user.get('isAdmin', False),
                        'suspended': True,  # These are all suspended users
                        'full_name': f"{user.get('name', {}).get('givenName', '')} {user.get('name', {}).get('familyName', '')}".strip()
                    }
                    formatted_suspended_users.append(user_data)
            
            return jsonify({
                'success': True,
                'users': formatted_suspended_users,
                'total_count': len(formatted_suspended_users)
            })
            
        except Exception as api_error:
            logging.error(f"Google API error: {api_error}")
            return jsonify({'success': False, 'error': f'Failed to retrieve suspended users: {str(api_error)}'})
            
    except Exception as e:
        logging.error(f"Load suspended users error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/change-domain-all-users', methods=['POST'])
@login_required
def api_change_domain_all_users():
    """Change domain for all users matching the current domain suffix"""
    try:
        # Check if user is authenticated
        if 'current_account_name' not in session:
            return jsonify({'success': False, 'error': 'No account authenticated. Please authenticate first.'})
        
        # Get the current authenticated account
        account_name = session.get('current_account_name')
        
        # First, try to authenticate using saved tokens if service is not available
        if not google_api.service:
            # Check if we have valid tokens for this account
            if google_api.is_token_valid(account_name):
                success = google_api.authenticate_with_tokens(account_name)
                if not success:
                    return jsonify({'success': False, 'error': 'Failed to authenticate with saved tokens. Please re-authenticate.'})
            else:
                return jsonify({'success': False, 'error': 'No valid tokens found. Please re-authenticate.'})
        
        # Get request data
        data = request.get_json()
        current_domain = data.get('current_domain', '').strip()
        new_domain = data.get('new_domain', '').strip()
        exclude_admin = data.get('exclude_admin', True)
        
        if not current_domain or not new_domain:
            return jsonify({'success': False, 'error': 'Both current and new domain are required'})
        
        if current_domain == new_domain:
            return jsonify({'success': False, 'error': 'Current and new domain cannot be the same'})
        
        try:
            # First try to get all users and filter by domain (more reliable)
            logging.info(f"Searching for users with domain: {current_domain}")
            
            # Get all users first (Google Admin API limit is 500)
            # Add timeout to prevent hanging
            all_users_result = google_api.service.users().list(
                customer='my_customer',
                maxResults=500
            ).execute()
            
            all_users = all_users_result.get('users', [])
            logging.info(f"Found {len(all_users)} total users")
            
            # Filter users by domain
            users = []
            for user in all_users:
                email = user.get('primaryEmail', '')
                if email and email.endswith(f"@{current_domain}"):
                    users.append(user)
            
            logging.info(f"Found {len(users)} users with domain {current_domain}")
            
            if not users:
                return jsonify({
                    'success': True,
                    'successful': 0,
                    'failed': 0,
                    'skipped': 0,
                    'message': f'No users found with domain {current_domain}'
                })
            
            successful = 0
            failed = 0
            skipped = 0
            results = []
            
            # Process users in smaller batches to avoid timeouts
            batch_size = 10
            total_users = len(users)
            
            for i, user in enumerate(users):
                try:
                    email = user.get('primaryEmail', '')
                    if not email:
                        continue
                    
                    # Check if user is admin (skip if exclude_admin is True)
                    if exclude_admin and user.get('isAdmin', False):
                        skipped += 1
                        results.append({
                            'email': email,
                            'skipped': True,
                            'reason': 'Admin user'
                        })
                        continue
                    
                    # Create new email with new domain
                    username = email.split('@')[0]
                    new_email = f"{username}@{new_domain}"
                    
                    # Update user's primary email
                    user_update = {
                        'primaryEmail': new_email
                    }
                    
                    logging.info(f"Updating user {i+1}/{total_users}: {email} → {new_email}")
                    
                    # Add timeout to the API call
                    google_api.service.users().update(
                        userKey=email,
                        body=user_update
                    ).execute()
                    
                    successful += 1
                    results.append({
                        'success': True,
                        'old_email': email,
                        'new_email': new_email
                    })
                    
                    logging.info(f"✅ Successfully updated user {i+1}/{total_users}: {email} → {new_email}")
                    
                    # Add small delay between API calls to avoid rate limiting
                    import time
                    time.sleep(0.1)
                    
                except Exception as user_error:
                    failed += 1
                    results.append({
                        'success': False,
                        'email': email,
                        'error': str(user_error)
                    })
                    logging.error(f"❌ Failed to update user {i+1}/{total_users} {email}: {user_error}")
                    
                    # Continue processing other users even if one fails
                    continue
            
            # Update domain usage in database
            try:
                from database import UsedDomain
                
                # Mark old domain as having 0 users
                old_domain_record = UsedDomain.query.filter_by(domain_name=current_domain).first()
                if old_domain_record:
                    old_domain_record.user_count = 0
                    old_domain_record.updated_at = db.func.current_timestamp()
                
                # Mark new domain as having users
                new_domain_record = UsedDomain.query.filter_by(domain_name=new_domain).first()
                if new_domain_record:
                    new_domain_record.user_count = successful
                    new_domain_record.updated_at = db.func.current_timestamp()
                else:
                    new_domain_record = UsedDomain(
                        domain_name=new_domain,
                        user_count=successful,
                        is_verified=True
                    )
                    db.session.add(new_domain_record)
                
                db.session.commit()
                logging.info(f"Updated domain usage: {current_domain} → {new_domain}, users: {successful}")
                
            except Exception as db_error:
                logging.warning(f"Failed to update domain usage in database: {db_error}")
                # Don't fail the entire operation for database update issues
            
            return jsonify({
                'success': True,
                'successful': successful,
                'failed': failed,
                'skipped': skipped,
                'results': results,
                'message': f'Domain change completed: {successful} users updated, {failed} failed, {skipped} skipped'
            })
            
        except Exception as api_error:
            logging.error(f"Google API error: {api_error}")
            return jsonify({'success': False, 'error': f'Failed to change domains: {str(api_error)}'})
            
    except Exception as e:
        logging.error(f"Change domain all users error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/debug-domain-users', methods=['POST'])
@login_required
def api_debug_domain_users():
    """Debug endpoint to check users for a specific domain"""
    try:
        # Check if user is authenticated
        if 'current_account_name' not in session:
            return jsonify({'success': False, 'error': 'No account authenticated. Please authenticate first.'})
        
        # Get the current authenticated account
        account_name = session.get('current_account_name')
        
        # First, try to authenticate using saved tokens if service is not available
        if not google_api.service:
            # Check if we have valid tokens for this account
            if google_api.is_token_valid(account_name):
                success = google_api.authenticate_with_tokens(account_name)
                if not success:
                    return jsonify({'success': False, 'error': 'Failed to authenticate with saved tokens. Please re-authenticate.'})
            else:
                return jsonify({'success': False, 'error': 'No valid tokens found. Please re-authenticate.'})
        
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'})
        
        try:
            # Get all users first (Google Admin API limit is 500)
            all_users_result = google_api.service.users().list(
                customer='my_customer',
                maxResults=500
            ).execute()
            
            all_users = all_users_result.get('users', [])
            
            # Filter users by domain
            domain_users = []
            for user in all_users:
                email = user.get('primaryEmail', '')
                if email and email.endswith(f"@{domain}"):
                    domain_users.append({
                        'email': email,
                        'name': user.get('name', {}),
                        'isAdmin': user.get('isAdmin', False),
                        'suspended': user.get('suspended', False)
                    })
            
            return jsonify({
                'success': True,
                'domain': domain,
                'total_users_found': len(all_users),
                'domain_users_found': len(domain_users),
                'domain_users': domain_users
            })
            
        except Exception as api_error:
            logging.error(f"Google API error: {api_error}")
            return jsonify({'success': False, 'error': f'Failed to retrieve users: {str(api_error)}'})
            
    except Exception as e:
        logging.error(f"Debug domain users error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/mark-domain-used', methods=['POST'])
@login_required
def api_mark_domain_used():
    """Mark a domain as used in the database"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'})
        
        from database import UsedDomain
        
        # Find or create domain record
        domain_record = UsedDomain.query.filter_by(domain_name=domain).first()
        if domain_record:
            domain_record.user_count = max(domain_record.user_count, 1)  # At least 1 user
            domain_record.updated_at = db.func.current_timestamp()
        else:
            domain_record = UsedDomain(
                domain_name=domain,
                user_count=1,
                is_verified=True
            )
            db.session.add(domain_record)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Domain {domain} marked as used'
        })
        
    except Exception as e:
        logging.error(f"Mark domain used error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/force-refresh-domains', methods=['POST'])
@login_required
def api_force_refresh_domains():
    """Force refresh domain data from Google Admin API and update database"""
    try:
        # Check if user is authenticated
        if 'current_account_name' not in session:
            return jsonify({'success': False, 'error': 'No account authenticated. Please authenticate first.'})
        
        # Get the current authenticated account
        account_name = session.get('current_account_name')
        
        # First, try to authenticate using saved tokens if service is not available
        if not google_api.service:
            # Check if we have valid tokens for this account
            if google_api.is_token_valid(account_name):
                success = google_api.authenticate_with_tokens(account_name)
                if not success:
                    return jsonify({'success': False, 'error': 'Failed to authenticate with saved tokens. Please re-authenticate.'})
            else:
                return jsonify({'success': False, 'error': 'No valid tokens found. Please re-authenticate.'})
        
        try:
            # Get all users with pagination
            all_users = []
            page_token = None
            
            while True:
                try:
                    if page_token:
                        users_result = google_api.service.users().list(
                            customer='my_customer',
                            maxResults=500,
                            pageToken=page_token
                        ).execute()
                    else:
                        users_result = google_api.service.users().list(
                            customer='my_customer',
                            maxResults=500
                        ).execute()
                    
                    users = users_result.get('users', [])
                    all_users.extend(users)
                    
                    page_token = users_result.get('nextPageToken')
                    if not page_token:
                        break
                        
                except Exception as e:
                    logging.warning(f"Failed to retrieve users page: {e}")
                    break
            
            logging.info(f"Force refresh: Retrieved {len(all_users)} total users")
            
            # Calculate user count per domain
            domain_user_counts = {}
            for user in all_users:
                email = user.get('primaryEmail', '')
                if email and '@' in email:
                    domain = email.split('@')[1]
                    domain_user_counts[domain] = domain_user_counts.get(domain, 0) + 1
            
            # Update database with real user counts
            from database import UsedDomain
            
            for domain_name, user_count in domain_user_counts.items():
                try:
                    existing_domain = UsedDomain.query.filter_by(domain_name=domain_name).first()
                    if existing_domain:
                        existing_domain.user_count = user_count
                        existing_domain.updated_at = db.func.current_timestamp()
                        logging.info(f"Updated domain {domain_name}: {user_count} users")
                    else:
                        new_domain = UsedDomain(
                            domain_name=domain_name,
                            user_count=user_count,
                            is_verified=True
                        )
                        db.session.add(new_domain)
                        logging.info(f"Added new domain {domain_name}: {user_count} users")
                except Exception as e:
                    logging.warning(f"Failed to update domain {domain_name}: {e}")
                    continue
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f'Domain data refreshed successfully. Found {len(domain_user_counts)} domains with {len(all_users)} total users.',
                'domains_updated': len(domain_user_counts),
                'total_users': len(all_users)
            })
            
        except Exception as api_error:
            logging.error(f"Google API error during force refresh: {api_error}")
            return jsonify({'success': False, 'error': f'Failed to refresh domains: {str(api_error)}'})
            
    except Exception as e:
        logging.error(f"Force refresh domains error: {e}")
        return jsonify({'success': False, 'error': str(e)})

# Settings page route
@app.route('/settings')
@login_required
def settings():
    if session.get('role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    return render_template('settings.html', user=session.get('user'), role=session.get('role'))

# Server configuration API routes
@app.route('/api/get-server-config', methods=['GET'])
@login_required
def get_server_config():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin privileges required'})
    
    try:
        from database import ServerConfig
        config = ServerConfig.query.first()
        if config:
            return jsonify({
                'success': True,
                'config': {
                    'host': config.host,
                    'port': config.port,
                    'username': config.username,
                    'auth_method': config.auth_method,
                    'password': config.password if config.password else '',
                    'private_key': config.private_key if config.private_key else '',
                    'json_path': config.json_path,
                    'file_pattern': config.file_pattern,
                    'is_configured': config.is_configured,
                    'last_tested': config.last_tested.isoformat() if config.last_tested else None
                }
            })
        else:
            return jsonify({'success': True, 'config': None})
    except Exception as e:
        app.logger.error(f"Error getting server config: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/save-server-config', methods=['POST'])
@login_required
def save_server_config():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin privileges required'})
    
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['host', 'username', 'json_path', 'file_pattern']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'Missing required field: {field}'})
        
        from database import ServerConfig
        
        # Get or create config
        config = ServerConfig.query.first()
        if not config:
            config = ServerConfig()
            db.session.add(config)
        
        # Update config
        config.host = data['host']
        config.port = data.get('port', 22)
        config.username = data['username']
        config.auth_method = data.get('auth_method', 'password')
        config.json_path = data['json_path']
        config.file_pattern = data['file_pattern']
        
        # Handle authentication credentials
        if data['auth_method'] == 'password':
            config.password = data.get('password', '')
            config.private_key = None
        else:
            config.private_key = data.get('private_key', '')
            config.password = None
        
        config.is_configured = True
        config.updated_at = db.func.current_timestamp()
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Server configuration saved successfully'})
        
    except Exception as e:
        app.logger.error(f"Error saving server config: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/test-server-connection', methods=['POST'])
@login_required
def test_server_connection():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin privileges required'})
    
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['host', 'username', 'json_path', 'file_pattern']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'Missing required field: {field}'})
        
        # Test SSH connection and file access
        import paramiko
        import tempfile
        import os
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Connect to server
            if data['auth_method'] == 'password':
                ssh.connect(
                    data['host'],
                    port=data.get('port', 22),
                    username=data['username'],
                    password=data.get('password', ''),
                    timeout=10
                )
            else:
                # Create temporary key file
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as key_file:
                    key_file.write(data.get('private_key', ''))
                    key_file_path = key_file.name
                
                try:
                    private_key = paramiko.RSAKey.from_private_key_file(key_file_path)
                    ssh.connect(
                        data['host'],
                        port=data.get('port', 22),
                        username=data['username'],
                        pkey=private_key,
                        timeout=10
                    )
                finally:
                    os.unlink(key_file_path)
            
            # Test file access
            sftp = ssh.open_sftp()
            try:
                # List files in the specified directory
                files = sftp.listdir(data['json_path'])
                
                # Filter files based on pattern
                import fnmatch
                json_files = [f for f in files if fnmatch.fnmatch(f, data['file_pattern'])]
                
                # Test reading a few files to ensure they're valid JSON
                valid_files = []
                for filename in json_files[:5]:  # Test first 5 files
                    try:
                        file_path = os.path.join(data['json_path'], filename)
                        with sftp.open(file_path, 'r') as f:
                            content = f.read()
                            json.loads(content)  # Validate JSON
                            valid_files.append(filename)
                    except Exception as e:
                        app.logger.warning(f"Invalid JSON file {filename}: {e}")
                        continue
                
                ssh.close()
                
                return jsonify({
                    'success': True,
                    'message': f'Connection successful. Found {len(valid_files)} valid JSON files.',
                    'files_count': len(valid_files),
                    'files': valid_files[:10]  # Return first 10 valid files
                })
                
            except Exception as e:
                ssh.close()
                return jsonify({'success': False, 'error': f'Failed to access files: {str(e)}'})
                
        except Exception as e:
            return jsonify({'success': False, 'error': f'SSH connection failed: {str(e)}'})
            
    except Exception as e:
        app.logger.error(f"Error testing server connection: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/clear-server-config', methods=['POST'])
@login_required
def clear_server_config():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin privileges required'})
    
    try:
        from database import ServerConfig
        config = ServerConfig.query.first()
        if config:
            db.session.delete(config)
            db.session.commit()
        
        return jsonify({'success': True, 'message': 'Server configuration cleared'})
        
    except Exception as e:
        app.logger.error(f"Error clearing server config: {e}")
        return jsonify({'success': False, 'error': str(e)})

# Enhanced Add from Server JSON functionality
@app.route('/api/add-from-server-json', methods=['POST'])
@login_required
def add_from_server_json():
    # Check if user is mailer role (not allowed to add accounts)
    if session.get('role') == 'mailer':
        return jsonify({'success': False, 'error': 'Mailer users cannot add accounts'})
    
    # Only admin and support users can add accounts
    if session.get('role') not in ['admin', 'support']:
        return jsonify({'success': False, 'error': 'Admin or support privileges required'})
    
    try:
        data = request.get_json()
        emails = data.get('emails', [])
        
        if not emails:
            return jsonify({'success': False, 'error': 'No email addresses provided'})
        
        # Get server configuration
        from database import ServerConfig
        config = ServerConfig.query.first()
        if not config or not config.is_configured:
            return jsonify({'success': False, 'error': 'Server not configured. Please configure server settings first.'})
        
        # Connect to server and retrieve JSON files
        import paramiko
        import tempfile
        import os
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Connect to server
            if config.auth_method == 'password':
                ssh.connect(
                    config.host,
                    port=config.port,
                    username=config.username,
                    password=config.password,
                    timeout=10
                )
            else:
                # Create temporary key file
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as key_file:
                    key_file.write(config.private_key)
                    key_file_path = key_file.name
                
                try:
                    private_key = paramiko.RSAKey.from_private_key_file(key_file_path)
                    ssh.connect(
                        config.host,
                        port=config.port,
                        username=config.username,
                        pkey=private_key,
                        timeout=10
                    )
                finally:
                    os.unlink(key_file_path)
            
            # Get JSON files
            sftp = ssh.open_sftp()
            try:
                files = sftp.listdir(config.json_path)
                
                # Filter files based on pattern
                import fnmatch
                json_files = [f for f in files if fnmatch.fnmatch(f, config.file_pattern)]
                
                # Process each email
                added_accounts = []
                failed_accounts = []
                
                for email in emails:
                    email = email.strip()
                    if not email or '@' not in email:
                        failed_accounts.append({'email': email, 'error': 'Invalid email format'})
                        continue
                    
                    # Look for matching JSON file
                    json_filename = f"{email}.json"
                    if json_filename in json_files:
                        try:
                            # Read and parse JSON file
                            file_path = os.path.join(config.json_path, json_filename)
                            with sftp.open(file_path, 'r') as f:
                                content = f.read()
                                json_data = json.loads(content)
                            
                            # Extract client credentials
                            if 'installed' in json_data:
                                client_data = json_data['installed']
                            elif 'web' in json_data:
                                client_data = json_data['web']
                            else:
                                failed_accounts.append({'email': email, 'error': 'Invalid JSON format'})
                                continue
                            
                            client_id = client_data.get('client_id')
                            client_secret = client_data.get('client_secret')
                            
                            if not client_id or not client_secret:
                                failed_accounts.append({'email': email, 'error': 'Missing client_id or client_secret'})
                                continue
                            
                            # Check if account already exists
                            from database import GoogleAccount
                            existing_account = GoogleAccount.query.filter_by(account_name=email).first()
                            if existing_account:
                                failed_accounts.append({'email': email, 'error': 'Account already exists'})
                                continue
                            
                            # Add new account
                            new_account = GoogleAccount(
                                account_name=email,
                                client_id=client_id,
                                client_secret=client_secret
                            )
                            db.session.add(new_account)
                            added_accounts.append(email)
                            
                        except Exception as e:
                            failed_accounts.append({'email': email, 'error': f'Failed to process file: {str(e)}'})
                            continue
                    else:
                        failed_accounts.append({'email': email, 'error': f'JSON file not found: {json_filename}'})
                
                # Commit all changes
                db.session.commit()
                
                ssh.close()
                
                # Prepare response message
                message = f"Successfully added {len(added_accounts)} account(s)."
                if failed_accounts:
                    message += f" Failed to add {len(failed_accounts)} account(s)."
                
                return jsonify({
                    'success': True,
                    'message': message,
                    'added_accounts': added_accounts,
                    'failed_accounts': failed_accounts
                })
                
            except Exception as e:
                ssh.close()
                return jsonify({'success': False, 'error': f'Failed to access files: {str(e)}'})
                
        except Exception as e:
            return jsonify({'success': False, 'error': f'SSH connection failed: {str(e)}'})
            
    except Exception as e:
        app.logger.error(f"Error adding from server JSON: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/test-smtp', methods=['POST'])
@login_required
def test_smtp_credentials():
    """Test SMTP credentials by sending test emails"""
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin privileges required'})
    
    try:
        data = request.get_json()
        credentials_text = data.get('credentials', '').strip()
        recipient_email = data.get('recipient_email', '').strip()
        smtp_server = data.get('smtp_server', 'smtp.gmail.com').strip()
        smtp_port = int(data.get('smtp_port', 587))
        
        if not credentials_text:
            return jsonify({'success': False, 'error': 'No credentials provided'})
        
        if not recipient_email or '@' not in recipient_email:
            return jsonify({'success': False, 'error': 'Invalid recipient email'})
        
        # Parse credentials (email:password format, one per line)
        credentials_lines = [line.strip() for line in credentials_text.split('\n') if line.strip()]
        results = []
        
        for line in credentials_lines:
            if ':' not in line:
                results.append({
                    'email': line,
                    'status': 'error',
                    'error': 'Invalid format - use email:password'
                })
                continue
            
            try:
                email, password = line.split(':', 1)
                email = email.strip()
                password = password.strip()
                
                if not email or not password:
                    results.append({
                        'email': email or 'unknown',
                        'status': 'error',
                        'error': 'Empty email or password'
                    })
                    continue
                
                # Test SMTP connection and send email
                import smtplib
                from email.mime.text import MIMEText
                from email.mime.multipart import MIMEMultipart
                import socket
                
                # Create message
                msg = MIMEMultipart()
                msg['From'] = email
                msg['To'] = recipient_email
                msg['Subject'] = f"SMTP Test from {email}"
                
                body = f"""
This is a test email sent from {email} using the GBot Web Application SMTP tester.

Test Details:
- Sender: {email}
- SMTP Server: {smtp_server}:{smtp_port}
- Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

If you received this email, the SMTP credentials are working correctly.
"""
                msg.attach(MIMEText(body, 'plain'))
                
                # Connect and send
                server = smtplib.SMTP(smtp_server, smtp_port)
                server.starttls()  # Enable encryption
                server.login(email, password)
                server.send_message(msg)
                server.quit()
                
                results.append({
                    'email': email,
                    'status': 'success',
                    'message': f'Test email sent successfully to {recipient_email}'
                })
                
            except smtplib.SMTPAuthenticationError as e:
                results.append({
                    'email': email,
                    'status': 'error',
                    'error': f'Authentication failed: {str(e)}'
                })
            except smtplib.SMTPException as e:
                results.append({
                    'email': email,
                    'status': 'error',
                    'error': f'SMTP error: {str(e)}'
                })
            except socket.gaierror as e:
                results.append({
                    'email': email,
                    'status': 'error',
                    'error': f'DNS/Network error: {str(e)}'
                })
            except Exception as e:
                results.append({
                    'email': email,
                    'status': 'error',
                    'error': f'Unexpected error: {str(e)}'
                })
        
        # Return results
        success_count = sum(1 for r in results if r['status'] == 'success')
        total_count = len(results)
        
        return jsonify({
            'success': True,
            'results': results,
            'summary': {
                'total': total_count,
                'successful': success_count,
                'failed': total_count - success_count
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error in SMTP testing: {e}")
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'})

@app.route('/api/bulk-upload-authenticated-accounts', methods=['POST'])
@login_required
def api_bulk_upload_authenticated_accounts():
    """Bulk upload authenticated Google accounts with tokens from JSON"""
    # Check if user is mailer role (not allowed to add accounts)
    if session.get('role') == 'mailer':
        return jsonify({'success': False, 'error': 'Mailer users cannot add accounts'})
    
    try:
        data = request.get_json()
        accounts_data = data.get('accounts', {})
        
        if not accounts_data:
            return jsonify({'success': False, 'error': 'No accounts data provided'})
        
        added_accounts = []
        failed_accounts = []
        
        for email, account_info in accounts_data.items():
            try:
                # Validate required fields for authenticated accounts
                required_fields = ['token', 'refresh_token', 'token_uri', 'client_id', 'client_secret', 'scopes']
                missing_fields = [field for field in required_fields if not account_info.get(field)]
                
                if missing_fields:
                    failed_accounts.append({
                        'email': email,
                        'error': f'Missing required fields: {", ".join(missing_fields)}'
                    })
                    continue
                
                # Validate email format
                if '@' not in email:
                    failed_accounts.append({
                        'email': email,
                        'error': 'Invalid email format'
                    })
                    continue
                
                # Check if account already exists
                existing_account = GoogleAccount.query.filter_by(account_name=email).first()
                if existing_account:
                    failed_accounts.append({
                        'email': email,
                        'error': 'Account already exists'
                    })
                    continue
                
                # Create new GoogleAccount
                new_account = GoogleAccount(
                    account_name=email,
                    client_id=account_info['client_id'],
                    client_secret=account_info['client_secret']
                )
                db.session.add(new_account)
                db.session.flush()  # Flush to get the account ID
                
                # Create GoogleToken with authentication data
                new_token = GoogleToken(
                    account_id=new_account.id,
                    token=account_info['token'],
                    refresh_token=account_info['refresh_token'],
                    token_uri=account_info['token_uri']
                )
                db.session.add(new_token)
                
                # Add scopes
                scopes = account_info.get('scopes', [])
                if isinstance(scopes, list):
                    for scope_name in scopes:
                        # Check if scope exists, create if not
                        scope = Scope.query.filter_by(name=scope_name).first()
                        if not scope:
                            scope = Scope(name=scope_name)
                            db.session.add(scope)
                            db.session.flush()  # Flush to get scope ID
                        
                        # Associate scope with token
                        new_token.scopes.append(scope)
                
                added_accounts.append(email)
                logging.info(f"Successfully added authenticated account: {email}")
                
            except Exception as e:
                logging.error(f"Error processing account {email}: {e}")
                failed_accounts.append({
                    'email': email,
                    'error': f'Processing error: {str(e)}'
                })
                continue
        
        # Commit all changes
        db.session.commit()
        
        # Prepare response
        added_count = len(added_accounts)
        failed_count = len(failed_accounts)
        
        if added_count > 0:
            message = f"Successfully added {added_count} authenticated account(s)"
            if failed_count > 0:
                message += f", {failed_count} failed"
        else:
            message = f"No accounts were added. {failed_count} failed"
        
        return jsonify({
            'success': True,
            'message': message,
            'added_count': added_count,
            'added_accounts': added_accounts,
            'failed_accounts': failed_accounts
        })
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Bulk upload error: {e}")
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'})

if __name__ == '__main__':
    app.run(debug=True)
