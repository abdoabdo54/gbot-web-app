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
    if request.endpoint in ['static', 'login', 'emergency_access']:
        return

    # IP Whitelist check - configurable via environment variables
    # Only check if explicitly enabled AND not in development mode
    if app.config.get('ENABLE_IP_WHITELIST', False) and not app.debug:
        client_ip = get_client_ip()
        whitelisted_ip = WhitelistedIP.query.filter_by(ip_address=client_ip).first()
        if not whitelisted_ip:
            return f"Access denied. IP {client_ip} not whitelisted.", 403
    # If IP whitelist is disabled or in development mode, allow all IPs

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
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user'] = user.username
            session['role'] = user.role
            flash(f'Welcome {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

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

@app.route('/whitelist')
@login_required
def whitelist():
    if session.get('role') != 'admin':
        flash("Admin access required.", "danger")
        return redirect(url_for('dashboard'))
    return render_template('whitelist.html', user=session.get('user'), role=session.get('role'))

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
        
        if new_role not in ['admin', 'support']:
            return jsonify({'success': False, 'error': 'Role must be admin or support'})
        
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
@login_required
def api_delete_whitelist_ip():
    if session.get('role') != 'admin':
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
        
        return jsonify({'success': True, 'message': f'IP address {ip_address} removed from whitelist'})
        
    except Exception as e:
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
                "redirect_uris": ["https://ecochain.site/oauth-callback"]
            }
        }
        
        flow = InstalledAppFlow.from_client_config(flow_config, app.config['SCOPES'])
        flow.redirect_uri = "https://ecochain.site/oauth-callback"
        
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

if __name__ == '__main__':
    app.run(debug=True)
