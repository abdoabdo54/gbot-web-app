# Main Flask app with routes

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import logging
import tempfile
import os
from datetime import datetime
from google_auth_oauthlib.flow import InstalledAppFlow
from core_logic import google_api
from config import SECRET_KEY, WHITELIST_TOKEN, REMOTE_DIR, REMOTE_ALT_DIR, SERVER_ADDRESS, SERVER_PORT, USERNAME, PASSWORD
import paramiko
import random
import string
import csv
import io
from faker import Faker
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json

# Add this debug check:
import os
print(f"DEBUG: SFTP_PASSWORD loaded: {'✓' if os.environ.get('SFTP_PASSWORD') else '✗'}")
print(f"DEBUG: SECRET_KEY loaded: {'✓' if os.environ.get('SECRET_KEY') else '✗'}")

SCOPES = [
    'https://www.googleapis.com/auth/admin.directory.user',
    'https://www.googleapis.com/auth/admin.directory.domain'
]

app = Flask(__name__)
app.secret_key = SECRET_KEY




# Used domains
used_domains = set()
USED_DOMAINS_FILENAME = 'used_domains.json'

# Whitelist IPs
WHITELIST_IPS_FILENAME = 'whitelist_ips.json'

# User storage persistent functions
USERS_FILENAME = 'users.json'

def load_whitelist_ips_from_server():
    """Load whitelisted IPs from SFTP server"""
    for remote_path in [f"{REMOTE_DIR}{WHITELIST_IPS_FILENAME}", f"{REMOTE_ALT_DIR}{WHITELIST_IPS_FILENAME}"]:
        try:
            transport = paramiko.Transport((SERVER_ADDRESS, SERVER_PORT))
            transport.connect(username=USERNAME, password=PASSWORD)
            sftp = paramiko.SFTPClient.from_transport(transport)
            
            with sftp.open(remote_path, 'r') as f:
                content = f.read()
            
            sftp.close()
            transport.close()
            
            if content.strip():
                ips_list = json.loads(content)
                print(f"STARTUP: Loaded {len(ips_list)} whitelisted IPs from SFTP: {ips_list}")
                return set(ips_list)
                
        except FileNotFoundError:
            print(f"Whitelist IPs file not found at {remote_path}, trying next location...")
            continue
        except Exception as e:
            print(f"Error loading whitelist IPs from {remote_path}: {e}")
            continue
    
    print("STARTUP: No whitelist IPs file found, starting with localhost only")
    return set(['127.0.0.1', '::1'])  # Default localhost

def save_whitelist_ips_to_server():
    """Save whitelisted IPs to SFTP server"""
    try:
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp_file:
            json.dump(list(allowed_ips), tmp_file, indent=2)
            tmp_file_path = tmp_file.name
        
        # Upload to both server locations
        success = False
        for remote_path in [f"{REMOTE_DIR}{WHITELIST_IPS_FILENAME}", f"{REMOTE_ALT_DIR}{WHITELIST_IPS_FILENAME}"]:
            try:
                transport = paramiko.Transport((SERVER_ADDRESS, SERVER_PORT))
                transport.connect(username=USERNAME, password=PASSWORD)
                sftp = paramiko.SFTPClient.from_transport(transport)
                
                sftp.put(tmp_file_path, remote_path)
                
                sftp.close()
                transport.close()
                
                print(f"DEBUG: Whitelist IPs saved to SFTP: {remote_path}")
                success = True
                break
                
            except Exception as e:
                print(f"Failed to save whitelist IPs to {remote_path}: {e}")
                continue
        
        # Clean up temp file
        os.unlink(tmp_file_path)
        return success
        
    except Exception as e:
        print(f"Error saving whitelist IPs to server: {e}")
        return False


# Simple IP whitelist storage (in memory for now)
allowed_ips = load_whitelist_ips_from_server()


def load_used_domains_from_server():
    """Load used domains from SFTP server"""
    for remote_path in [f"{REMOTE_DIR}{USED_DOMAINS_FILENAME}", f"{REMOTE_ALT_DIR}{USED_DOMAINS_FILENAME}"]:
        try:
            transport = paramiko.Transport((SERVER_ADDRESS, SERVER_PORT))
            transport.connect(username=USERNAME, password=PASSWORD)
            sftp = paramiko.SFTPClient.from_transport(transport)
            
            with sftp.open(remote_path, 'r') as f:
                content = f.read()
            
            sftp.close()
            transport.close()
            
            if content.strip():
                domains_list = json.loads(content)
                print(f"STARTUP: Loaded {len(domains_list)} used domains from SFTP: {domains_list}")
                return set(domains_list)
                
        except FileNotFoundError:
            print(f"Used domains file not found at {remote_path}, trying next location...")
            continue
        except Exception as e:
            print(f"Error loading used domains from {remote_path}: {e}")
            continue
    
    print("STARTUP: No used domains file found, starting with empty set")
    return set()

def save_used_domains_to_server():
    """Save used domains to SFTP server"""
    try:
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp_file:
            json.dump(list(used_domains), tmp_file, indent=2)
            tmp_file_path = tmp_file.name
        
        # Upload to both server locations
        success = False
        for remote_path in [f"{REMOTE_DIR}{USED_DOMAINS_FILENAME}", f"{REMOTE_ALT_DIR}{USED_DOMAINS_FILENAME}"]:
            try:
                transport = paramiko.Transport((SERVER_ADDRESS, SERVER_PORT))
                transport.connect(username=USERNAME, password=PASSWORD)
                sftp = paramiko.SFTPClient.from_transport(transport)
                
                sftp.put(tmp_file_path, remote_path)
                
                sftp.close()
                transport.close()
                
                print(f"DEBUG: Used domains saved to SFTP: {remote_path}")
                success = True
                break  # Success, no need to try other location
                
            except Exception as e:
                print(f"Failed to save used domains to {remote_path}: {e}")
                continue
        
        # Clean up temp file
        os.unlink(tmp_file_path)
        
        return success
        
    except Exception as e:
        print(f"Error saving used domains to server: {e}")
        return False


def load_users_from_server():
    """Load users from SFTP server"""
    for remote_path in [f"{REMOTE_DIR}{USERS_FILENAME}", f"{REMOTE_ALT_DIR}{USERS_FILENAME}"]:
        try:
            transport = paramiko.Transport((SERVER_ADDRESS, SERVER_PORT))
            transport.connect(username=USERNAME, password=PASSWORD)
            sftp = paramiko.SFTPClient.from_transport(transport)
            
            with sftp.open(remote_path, 'r') as f:
                content = f.read()
            
            sftp.close()
            transport.close()
            
            if content.strip():
                users_data = json.loads(content)
                print(f"STARTUP: Loaded {len(users_data)} users from SFTP")
                return users_data
                
        except FileNotFoundError:
            print(f"Users file not found at {remote_path}, trying next location...")
            continue
        except Exception as e:
            print(f"Error loading users from {remote_path}: {e}")
            continue
    
    print("STARTUP: No users file found, using default admin/support")
    return {
        'admin': {'password': 'A9B3nX#Q8k$mZ6vw', 'role': 'admin'},
        'support': {'password': 'SK7pW@R5j#nM4u2t', 'role': 'support'}
    }

def save_users_to_server():
    """Save users to SFTP server"""
    global app_users
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp_file:
            json.dump(app_users, tmp_file, indent=2)
            tmp_file_path = tmp_file.name
        
        success = False
        for remote_path in [f"{REMOTE_DIR}{USERS_FILENAME}", f"{REMOTE_ALT_DIR}{USERS_FILENAME}"]:
            try:
                transport = paramiko.Transport((SERVER_ADDRESS, SERVER_PORT))
                transport.connect(username=USERNAME, password=PASSWORD)
                sftp = paramiko.SFTPClient.from_transport(transport)
                
                sftp.put(tmp_file_path, remote_path)
                
                sftp.close()
                transport.close()
                
                print(f"DEBUG: Users saved to SFTP: {remote_path}")
                success = True
                break
                
            except Exception as e:
                print(f"Failed to save users to {remote_path}: {e}")
                continue
        
        os.unlink(tmp_file_path)
        return success
        
    except Exception as e:
        print(f"Error saving users to server: {e}")
        return False


# Load users from SFTP on startup
app_users = load_users_from_server()

# Login routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in app_users and app_users[username]['password'] == password:
            session['user'] = username
            session['role'] = app_users[username]['role']
            flash(f'Welcome {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

# Load used domains on startup from SFTP
used_domains = load_used_domains_from_server()

def check_ip():
    """Check if current IP is whitelisted"""
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    return client_ip in allowed_ips

def login_required(f):
    """Decorator to require login"""
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.before_request
def before_request():
    """Check IP whitelist before every request"""
    # Skip IP check for emergency access
    if request.path.startswith('/emergency-access/'):
        return None
        
    # Skip IP check for static files and login
    if request.endpoint in ['static', 'login']:
        return None
        
    client_ip = get_client_ip()
    if client_ip not in allowed_ips:
        return f"Access denied. IP {client_ip} not whitelisted.", 403

def get_client_ip():
    """Get the real client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def load_token_status_cache():
    """Load cached token status from SFTP"""
    try:
        for remote_path in [f"{REMOTE_DIR}token_status.json", f"{REMOTE_ALT_DIR}token_status.json"]:
            try:
                transport = paramiko.Transport((SERVER_ADDRESS, SERVER_PORT))
                transport.connect(username=USERNAME, password=PASSWORD)
                sftp = paramiko.SFTPClient.from_transport(transport)
                
                with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                    sftp.get(remote_path, tmp_file.name)
                    
                with open(tmp_file.name, 'r') as f:
                    cache_data = json.load(f)
                
                os.unlink(tmp_file.name)
                sftp.close()
                transport.close()
                
                return cache_data
                
            except Exception:
                continue
                
        return {'status': {}, 'last_updated': '2000-01-01T00:00:00'}
        
    except Exception as e:
        return {'status': {}, 'last_updated': '2000-01-01T00:00:00'}

def save_token_status_cache(cache_data):
    """Save token status cache to SFTP"""
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp_file:
            json.dump(cache_data, tmp_file, indent=2)
            tmp_file_path = tmp_file.name
        
        for remote_path in [f"{REMOTE_DIR}token_status.json", f"{REMOTE_ALT_DIR}token_status.json"]:
            try:
                transport = paramiko.Transport((SERVER_ADDRESS, SERVER_PORT))
                transport.connect(username=USERNAME, password=PASSWORD)
                sftp = paramiko.SFTPClient.from_transport(transport)
                
                sftp.put(tmp_file_path, remote_path)
                
                sftp.close()
                transport.close()
                print(f"Token status cache saved to {remote_path}")
                break
                
            except Exception:
                continue
        
        os.unlink(tmp_file_path)
        
    except Exception as e:
        print(f"Failed to save token status cache: {e}")

@app.route('/api/save-token-status-cache', methods=['POST'])
@login_required
def api_save_token_status_cache():
    """Save token status results for persistence"""
    try:
        data = request.get_json()
        status_results = data.get('status_results', {})
        
        cache_data = {
            'status': status_results,
            'last_updated': datetime.now().isoformat(),
            'total_accounts': len(status_results)
        }
        
        # Save to SFTP
        save_token_status_cache(cache_data)
        
        print(f"Token status saved: {len(status_results)} accounts")
        return jsonify({'success': True, 'message': 'Token status saved'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/load-token-status-cache', methods=['POST'])
@login_required
def api_load_token_status_cache():
    """Load saved token status for persistence"""
    try:
        cache_data = load_token_status_cache()
        
        if cache_data and cache_data.get('status'):
            print(f"Token status loaded: {len(cache_data['status'])} accounts")
            return jsonify({'success': True, 'status': cache_data['status']})
        else:
            print("No token status cache found")
            return jsonify({'success': False, 'message': 'No cache found'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
        
@app.route('/users')
@login_required
def users():
    # Admin only access
    if session.get('role') != 'admin':
        flash("Admin access required.", "danger")
        return redirect(url_for('dashboard'))
    return render_template('users.html',
                         user=session.get('user'),
                         role=session.get('role'))

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
        
        if username in app_users:
            return jsonify({'success': False, 'error': 'Username already exists'})
        
        # Add user
        app_users[username] = {'password': password, 'role': role}
        save_users_to_server()
        
        return jsonify({'success': True, 'message': f'User {username} created successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/list-users', methods=['GET'])
@login_required
def api_list_users():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    try:
        user_list = [{'username': username, 'role': data['role']} for username, data in app_users.items()]
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
        
        if username not in app_users:
            return jsonify({'success': False, 'error': 'User not found'})
        
        if not new_password:
            return jsonify({'success': False, 'error': 'Password required'})
        
        if new_role not in ['admin', 'support']:
            return jsonify({'success': False, 'error': 'Role must be admin or support'})
        
        # Update user
        app_users[username]['password'] = new_password
        app_users[username]['role'] = new_role
        
        # Save to SFTP
        save_users_to_server()
        
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
        
        if username not in app_users:  # Change from 'users' to 'app_users'
            return jsonify({'success': False, 'error': 'User not found'})
        
        if username == session.get('user'):
            return jsonify({'success': False, 'error': 'Cannot delete your own account'})
        
        # Delete user
        del app_users[username]  # Change from 'users' to 'app_users'
        save_users_to_server()
        
        return jsonify({'success': True, 'message': f'User {username} deleted successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Emergency IP whitelisting route
@app.route('/emergency-access/<token>')
def emergency_access(token):
    if token == WHITELIST_TOKEN:
        client_ip = get_client_ip()
        allowed_ips.add(client_ip)
        
        # Save to SFTP
        if save_whitelist_ips_to_server():
            message = f"IP {client_ip} has been whitelisted and saved to SFTP!"
            print(f"EMERGENCY ACCESS: {client_ip} whitelisted and saved")
        else:
            message = f"IP {client_ip} has been whitelisted locally (SFTP save failed)"
            print(f"EMERGENCY ACCESS: {client_ip} whitelisted locally only")
        
        return f"<h1>✅ Access Granted</h1><p>{message}</p><p><a href='/'>Go to Dashboard</a></p>"
    else:
        return "Invalid token", 403


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

# Main dashboard
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    # Load accounts from SFTP
    accounts = google_api.load_accounts_from_server()
    return render_template('dashboard.html', 
                         accounts=accounts, 
                         user=session.get('user'),
                         role=session.get('role'))

# API Routes
@app.route('/api/authenticate', methods=['POST'])
@login_required
def api_authenticate():
    try:
        data = request.get_json()
        account_name = data.get('account_name')
        
        if not account_name:
            return jsonify({'success': False, 'error': 'No account specified'})
        
        # Load accounts
        accounts = google_api.load_accounts_from_server()
        if account_name not in accounts:
            return jsonify({'success': False, 'error': 'Account not found'})
        
        # Check for existing tokens firstn 
        if google_api.is_token_valid(account_name):
            success = google_api.authenticate_with_tokens(account_name)
            if success:
                session['authenticated_account'] = account_name
                return jsonify({
                    'success': True, 
                    'message': f'Authenticated using cached tokens for {account_name}'
                })
        
        # Generate OAuth URL for manual authentication
        oauth_url = google_api.get_oauth_url(account_name, accounts)
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
        
        # Load current accounts
        accounts = google_api.load_accounts_from_server()
        
        # Add new account
        accounts[account_name] = {
            'client_id': client_id,
            'client_secret': client_secret
        }
        
        # Save back to server (you'll need to implement this)
        success = save_accounts_to_server(accounts)
        
        if success:
            return jsonify({'success': True, 'message': f'Account {account_name} added successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to save account to server'})
            
    except Exception as e:
        logging.error(f"Add account error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/oauth-callback')
def oauth_callback():
    """Show code for manual entry in main app"""
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
    """Complete OAuth with authorization code"""
    try:
        data = request.get_json()
        auth_code = data.get('auth_code')
        account_name = data.get('account_name')
        
        if not auth_code or not account_name:
            return jsonify({'success': False, 'error': 'Code and account name required'})
        
        # Load account credentials
        accounts = google_api.load_accounts_from_server()
        if account_name not in accounts:
            return jsonify({'success': False, 'error': 'Account not found'})
        
        creds_data = accounts[account_name]
        
        # Exchange code for tokens (same as V13 desktop)
        flow_config = {
            "installed": {
                "client_id": creds_data['client_id'],
                "project_id": "gbot-project",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth", 
                "token_uri": "https://oauth2.googleapis.com/token", 
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs", 
                "client_secret": creds_data['client_secret'], 
                "redirect_uris": ["https://gworkspace.edutrack.shop/oauth-callback"]
            }
        }
        
        flow = InstalledAppFlow.from_client_config(flow_config, SCOPES)
        flow.redirect_uri = "https://gworkspace.edutrack.shop/oauth-callback"
        
        # Exchange code for credentials (like V13 desktop)
        flow.fetch_token(code=auth_code)
        credentials = flow.credentials
        
        # Save tokens (like V13 desktop)
        current_tokens = google_api.load_tokens_from_server()
        current_tokens[account_name] = json.loads(credentials.to_json())
        google_api.save_tokens_to_server(current_tokens)
        
        return jsonify({'success': True, 'message': f'Authentication completed for {account_name}'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
        
@app.route('/api/check-token-status', methods=['POST'])
@login_required
def api_check_token_status():
    try:
        data = request.get_json()
        account_name = data.get('account_name')
        
        # Check if token exists and is valid
        is_valid = google_api.is_token_valid(account_name)
        
        return jsonify({'success': True, 'is_valid': is_valid})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/delete-account', methods=['POST'])
@login_required
def api_delete_account():
    try:
        data = request.get_json()
        account_name = data.get('account_name')
        
        if not account_name:
            return jsonify({'success': False, 'error': 'Account name required'})
        
        # Load current accounts
        accounts = google_api.load_accounts_from_server()
        
        if account_name not in accounts:
            return jsonify({'success': False, 'error': 'Account not found'})
        
        # Remove account
        del accounts[account_name]
        
        # Save back to server
        success = save_accounts_to_server(accounts)
        
        if success:
            return jsonify({'success': True, 'message': f'Account {account_name} deleted successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to save changes to server'})
            
    except Exception as e:
        logging.error(f"Delete account error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/create-random-users', methods=['POST'])
@login_required
def api_create_random_users():
    try:
        data = request.get_json()
        num_users = int(data.get('num_users', 0))
        domain = data.get('domain', '').strip()
        
        if num_users <= 0 or num_users > 100:
            return jsonify({'success': False, 'error': 'Number of users must be between 1-100'})
        
        if not domain or '.' not in domain:
            return jsonify({'success': False, 'error': 'Valid domain required'})
        
        # Generate random password
        import random
        import string
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        
        results = []
        from faker import Faker
        fake = Faker()
        
        for i in range(num_users):
            first_name = fake.first_name()
            last_name = fake.last_name()
            alias = f"{first_name.lower()}.{last_name.lower()}{random.randint(1,999)}"
            email = f"{alias}@{domain}"
            
            user_info = {
                "primaryEmail": email,
                "name": {"givenName": first_name, "familyName": last_name},
                "password": password,
                "changePasswordAtNextLogin": False,
                "orgUnitPath": "/"
            }
            
            # This would call your Google API create user function
            # For now, let's simulate it
            result = google_api.create_user(user_info)  # You need to implement this in core_logic.py
            results.append({"email": email, "result": result})
        
        return jsonify({
            "success": True,
            "results": results,
            "password": password,
            "created_count": num_users
        })
        
    except Exception as e:
        logging.error(f"Create random users error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/delete-users', methods=['POST'])
@login_required
def api_delete_users():
    try:
        data = request.get_json()
        user_emails = data.get('user_emails', [])
        
        if not user_emails:
            return jsonify({'success': False, 'error': 'No user emails provided'})
        
        results = []
        for email in user_emails:
            # This would call your Google API delete user function
            result = google_api.delete_user(email)  # You need to implement this in core_logic.py
            results.append({"email": email, "result": result})
        
        return jsonify({
            "success": True,
            "results": results
        })
        
    except Exception as e:
        logging.error(f"Delete users error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/change-domain', methods=['POST'])
@login_required
def api_change_domain():
    try:
        data = request.get_json()
        old_domain = data.get('old_domain', '').strip()
        new_domain = data.get('new_domain', '').strip()
        user_emails = data.get('user_emails', [])
        
        if not old_domain or not new_domain:
            return jsonify({'success': False, 'error': 'Both old and new domains required'})
        
        if not user_emails:
            return jsonify({'success': False, 'error': 'No user emails provided'})
        
        results = []
        for email in user_emails:
            # This would call your Google API change domain function
            # For now, let's simulate it
            if old_domain in email:
                new_email = email.replace(old_domain, new_domain)
                # You need to implement domain change in core_logic.py
                result = {"success": True, "old_email": email, "new_email": new_email}
            else:
                result = {"success": False, "email": email, "error": f"Email doesn't contain {old_domain}"}
            
            results.append(result)
        
        return jsonify({
            "success": True,
            "results": results
        })
        
    except Exception as e:
        logging.error(f"Change domain error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/create-users-from-csv', methods=['POST'])
@login_required
def api_create_users_from_csv():
    try:
        if 'csv_file' not in request.files:
            return jsonify({'success': False, 'error': 'No CSV file uploaded'})
        
        file = request.files['csv_file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})
        
        # Read and process CSV
        import csv
        import io
        
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_input = csv.DictReader(stream)
        
        results = []
        created_count = 0
        
        for row in csv_input:
            email = row.get('Email Address [Required]', '').strip()
            first_name = row.get('First Name [Required]', '').strip()
            last_name = row.get('Last Name [Required]', '').strip()
            password = row.get('Password [Required]', '').strip()
            
            if not all([email, first_name, last_name, password]):
                results.append({"email": email or "Unknown", "success": False, "error": "Missing required fields"})
                continue
            
            user_info = {
                "primaryEmail": email,
                "name": {"givenName": first_name, "familyName": last_name},
                "password": password,
                "changePasswordAtNextLogin": False,
                "orgUnitPath": "/"
            }
            
            # Call Google API to create user
            result = google_api.create_user(user_info)
            if result.get('success'):
                created_count += 1
            
            results.append({"email": email, "success": result.get('success', False), "error": result.get('error', '')})
        
        return jsonify({
            "success": True,
            "results": results,
            "created_count": created_count
        })
        
    except Exception as e:
        logging.error(f"Create users from CSV error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/test-smtp', methods=['POST'])
@login_required
def api_test_smtp():
    try:
        data = request.get_json()
        credentials_text = data.get('credentials', '').strip()
        recipient_email = data.get('recipient_email', '').strip()
        smtp_server = data.get('smtp_server', 'smtp.gmail.com')
        smtp_port = int(data.get('smtp_port', 587))
        
        if not credentials_text:
            return jsonify({'success': False, 'error': 'No credentials provided'})
        
        if not recipient_email or '@' not in recipient_email:
            return jsonify({'success': False, 'error': 'Valid recipient email required'})
        
        # Parse credentials
        credential_lines = [line.strip() for line in credentials_text.splitlines() if line.strip()]
        
        if not credential_lines:
            return jsonify({'success': False, 'error': 'No valid credentials found'})
        
        # Test SMTP credentials
        results = test_smtp_credentials(credential_lines, recipient_email, smtp_server, smtp_port)
        
        return jsonify({'success': True, 'results': results})
        
    except Exception as e:
        logging.error(f"SMTP test error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/generate-csv', methods=['POST'])
@login_required
def api_generate_csv():
    try:
        data = request.get_json()
        num_users = int(data.get('num_users', 0))
        domain = data.get('domain', '').strip()
        password = data.get('password', '').strip()
        
        if num_users <= 0 or num_users > 1000:
            return jsonify({'success': False, 'error': 'Number of users must be between 1-1000'})
        
        if not domain or '@' in domain or '.' not in domain:
            return jsonify({'success': False, 'error': 'Valid domain required (e.g., example.com)'})
        
        if not password:
            return jsonify({'success': False, 'error': 'Password required'})
        
        # Generate CSV data
        csv_data = generate_user_csv(num_users, domain, password)
        
        return jsonify({
            'success': True,
            'csv_data': csv_data
        })
        
    except Exception as e:
        logging.error(f"Generate CSV error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/preview-csv', methods=['POST'])
@login_required
def api_preview_csv():
    try:
        data = request.get_json()
        num_users = min(int(data.get('num_users', 5)), 10)  # Max 10 for preview
        domain = data.get('domain', 'example.com').strip()
        password = data.get('password', 'DefaultPass123').strip()
        
        # Generate preview data
        preview_data = generate_user_csv(num_users, domain, password)
        
        # Get first few lines for preview
        lines = preview_data.split('\n')
        preview_lines = lines[:min(len(lines), num_users + 2)]  # Header + preview rows
        preview = '\n'.join(preview_lines)
        
        return jsonify({
            'success': True,
            'preview': preview
        })
        
    except Exception as e:
        logging.error(f"Preview CSV error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/download-users-csv', methods=['POST'])
@login_required
def api_download_users_csv():
    try:
        if not google_api.service:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        # Get all users
        result = google_api.retrieve_active_users()
        
        if not result.get('success'):
            return jsonify({'success': False, 'error': result.get('error', 'Failed to retrieve users')})
        
        users = result.get('users', [])
        
        # Generate CSV for domain change
        csv_data = generate_domain_change_csv(users)
        
        return jsonify({
            'success': True,
            'csv_data': csv_data,
            'user_count': len(users)
        })
        
    except Exception as e:
        logging.error(f"Download users CSV error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/apply-domain-to-csv', methods=['POST'])
@login_required
def api_apply_domain_to_csv():
    try:
        data = request.get_json()
        selected_domain = data.get('selected_domain')
        csv_path = data.get('csv_path')
        
        if not selected_domain:
            return jsonify({'success': False, 'error': 'No domain selected'})
        
        # Get current users to modify their CSV data
        result = google_api.retrieve_active_users()
        if not result.get('success'):
            return jsonify({'success': False, 'error': 'Failed to retrieve current users'})
        
        users = result.get('users', [])
        
        # Generate modified CSV with new domain applied
        modified_csv_data = apply_domain_to_csv_data(users, selected_domain)
        modified_csv_path = csv_path.replace('.csv', f'_modified_{selected_domain.split(".")[0]}.csv')
        
        # Count users that will be modified
        modified_count = len([u for u in users if not u.get('admin', False)])
        
        return jsonify({
            'success': True,
            'modified_csv_path': modified_csv_path,
            'modified_csv_data': modified_csv_data,
            'modified_count': modified_count,
            'message': f'CSV modified to use domain: {selected_domain}'
        })
        
    except Exception as e:
        logging.error(f"Apply domain to CSV error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/process-csv-domain-changes', methods=['POST'])
@login_required
def api_process_csv_domain_changes():
    try:
        data = request.get_json()
        csv_path = data.get('csv_path')
        
        if not csv_path:
            return jsonify({'success': False, 'error': 'No CSV file specified'})
        
        if not google_api.service:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        # For web app, we'll use the modified CSV data stored in session/memory
        # In a real desktop app, you'd read the actual file
        
        # Get all current users
        result = google_api.retrieve_active_users()
        if not result.get('success'):
            return jsonify({'success': False, 'error': 'Failed to retrieve users'})
        
        users = result.get('users', [])
        
        # Process domain changes for non-admin users
        results = []
        successful = 0
        failed = 0
        skipped = 0
        
        for user in users:
            old_email = user.get('email')
            is_admin = user.get('admin', False)
            
            # Skip admin users
            if is_admin:
                results.append({
                    'email': old_email,
                    'skipped': True,
                    'reason': 'Admin user - excluded from bulk changes'
                })
                skipped += 1
                continue
            
            # Extract domain change from CSV logic would go here
            # For now, we'll simulate based on the selected domain pattern
            # In reality, you'd parse the actual CSV file
            
            try:
                # This would be replaced with actual CSV parsing
                # For now, we simulate the change
                change_result = process_single_user_domain_change(old_email)
                
                if change_result.get('success'):
                    results.append({
                        'old_email': old_email,
                        'new_email': change_result.get('new_email'),
                        'success': True
                    })
                    successful += 1
                else:
                    results.append({
                        'email': old_email,
                        'success': False,
                        'error': change_result.get('error', 'Unknown error')
                    })
                    failed += 1
                    
            except Exception as e:
                results.append({
                    'email': old_email,
                    'success': False,
                    'error': str(e)
                })
                failed += 1
        
        return jsonify({
            'success': True,
            'results': results,
            'successful': successful,
            'failed': failed,
            'skipped': skipped,
            'message': 'CSV domain changes processed'
        })
        
    except Exception as e:
        logging.error(f"Process CSV domain changes error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/change-domain-all-users', methods=['POST'])
@login_required
def api_change_domain_all_users():
    try:
        data = request.get_json()
        current_domain = data.get('current_domain', '').strip()
        new_domain = data.get('new_domain', '').strip()
        exclude_admin = data.get('exclude_admin', True)
        
        if not current_domain or not new_domain:
            return jsonify({'success': False, 'error': 'Both current and new domains required'})
        
        if not google_api.service:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        # Get all users
        result = google_api.retrieve_active_users()
        if not result.get('success'):
            return jsonify({'success': False, 'error': 'Failed to retrieve users'})
        
        users = result.get('users', [])
        
        # Filter users by current domain
        target_users = []
        for user in users:
            email = user.get('email', '')
            is_admin = user.get('admin', False)
            
            # Skip admin users if exclude_admin is True
            if exclude_admin and is_admin:
                continue
            
            # Check if user already has the new domain
            if new_domain in email:
                continue  # Skip users who already have the target domain
                
            # Check if user has the current domain
            if current_domain in email:
                target_users.append(user)
        
        if not target_users:
            return jsonify({
                'success': True,
                'results': [],
                'successful': 0,
                'failed': 0,
                'skipped': 0,
                'message': f'No users found with domain {current_domain}'
            })
        
# Process domain changes - REAL BATCH VERSION
        results = []
        successful = 0
        failed = 0
        skipped = 0
        
        # Prepare email changes for batch processing
        email_changes = []
        for user in target_users:
            old_email = user.get('email')
            if exclude_admin and user.get('admin', False):
                results.append({
                    'email': old_email,
                    'skipped': True,
                    'reason': 'Admin user excluded'
                })
                skipped += 1
                continue
            new_email = old_email.replace(current_domain, new_domain)
            email_changes.append((old_email, new_email))
        
        # REAL batch processing that actually changes domains
        if email_changes:
            print(f"DEBUG: Batch processing {len(email_changes)} users...")
            batch_result = google_api.batch_update_user_emails(email_changes)
            
            if batch_result.get('success'):
                results.extend(batch_result['results'])
                successful = sum(1 for r in batch_result['results'] if r['success'])
                failed = sum(1 for r in batch_result['results'] if not r['success'])
                print(f"DEBUG: Batch complete - {successful} success, {failed} failed")
            else:
                failed = len(email_changes)
                for old_email, new_email in email_changes:
                    results.append({
                        'email': old_email,
                        'success': False,
                        'error': batch_result['error']
                    })

        return jsonify({
            'success': True,
            'results': results,
            'successful': successful,
            'failed': failed,
            'skipped': skipped,
            'total_processed': len(target_users),
            'message': f'Bulk domain change completed: {current_domain} → {new_domain}'
        })
        
    except Exception as e:
        logging.error(f"Change domain all users error: {e}")
        return jsonify({'success': False, 'error': str(e)})

# Store used domains in memory (in production, use database)

@app.route('/api/mark-domain-used', methods=['POST'])
@login_required
def api_mark_domain_used():
    print(f"DEBUG: mark-domain-used called from IP: {get_client_ip()}")
    print(f"DEBUG: allowed_ips: {list(allowed_ips)}")
    try:
        data = request.get_json()
        domain = data.get('domain')
        
        if domain:
            used_domains.add(domain)
            
            # Save to SFTP server
            if save_used_domains_to_server():
                print(f"DEBUG: Domain '{domain}' added and saved to SFTP. Current used domains: {list(used_domains)}")
                logging.info(f"Domain marked as used and saved to SFTP: {domain}")
                return jsonify({'success': True, 'message': f'Domain {domain} marked as used'})
            else:
                print(f"WARNING: Domain '{domain}' added locally but failed to save to SFTP")
                return jsonify({'success': True, 'message': f'Domain {domain} marked as used (local only - SFTP save failed)'})
        else:
            return jsonify({'success': False, 'error': 'No domain provided'})
            
    except Exception as e:
        logging.error(f"Mark domain used error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/get-used-domains', methods=['GET'])
@login_required
def api_get_used_domains():
    try:
        return jsonify({'success': True, 'used_domains': list(used_domains)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def save_accounts_to_server(accounts):
    """Save accounts back to SFTP server"""
    try:
        import tempfile
        import json
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp_file:
            json.dump(accounts, tmp_file, indent=2)
            tmp_file_path = tmp_file.name
        
        success = False
        
        # Upload to server (main accounts file)
        for remote_path in [f"{REMOTE_DIR}accounts.json", f"{REMOTE_ALT_DIR}accounts.json"]:
            try:
                transport = paramiko.Transport((SERVER_ADDRESS, SERVER_PORT))
                transport.connect(username=USERNAME, password=PASSWORD)
                sftp = paramiko.SFTPClient.from_transport(transport)
                
                sftp.put(tmp_file_path, remote_path)
                
                sftp.close()
                transport.close()
                
                logging.info(f"Accounts saved to {remote_path}")
                success = True
                break
                
            except Exception as e:
                logging.warning(f"Failed to save to {remote_path}: {e}")
                continue
        
        # BACKUP 1: ARCHIVE-style SFTP backup (only add, never remove)
        for backup_remote_path in [f"{REMOTE_DIR}accounts_backup.json", f"{REMOTE_ALT_DIR}accounts_backup.json"]:
            try:
                transport = paramiko.Transport((SERVER_ADDRESS, SERVER_PORT))
                transport.connect(username=USERNAME, password=PASSWORD)
                sftp = paramiko.SFTPClient.from_transport(transport)
                
                # Load existing backup
                existing_backup = {}
                try:
                    with sftp.open(backup_remote_path, 'r') as f:
                        existing_backup = json.loads(f.read())
                except:
                    pass  # File doesn't exist yet
                
                # Merge: keep all old accounts + add new ones
                merged_backup = existing_backup.copy()
                merged_backup.update(accounts)  # Add new accounts, keep old ones
                
                # Save merged backup
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as backup_tmp:
                    json.dump(merged_backup, backup_tmp, indent=2)
                    backup_tmp_path = backup_tmp.name
                
                sftp.put(backup_tmp_path, backup_remote_path)
                os.unlink(backup_tmp_path)
                
                sftp.close()
                transport.close()
                
                print(f"✅ BACKUP 1: Archived to {backup_remote_path} ({len(merged_backup)} total accounts)")
                break
                
            except Exception as e:
                print(f"❌ BACKUP 1 failed: {backup_remote_path}: {e}")
                continue
        
        # BACKUP 2: ARCHIVE-style local backup (only add, never remove)
        try:
            local_backup_path = "/home/gbot/gbot_webapp/backup/accounts_backup.json"
            
            # Load existing local backup
            existing_local_backup = {}
            try:
                with open(local_backup_path, 'r') as f:
                    existing_local_backup = json.load(f)
            except:
                pass  # File doesn't exist yet
            
            # Merge: keep all old accounts + add new ones
            merged_local_backup = existing_local_backup.copy()
            merged_local_backup.update(accounts)  # Add new accounts, keep old ones
            
            # Save merged backup
            with open(local_backup_path, 'w') as f:
                json.dump(merged_local_backup, f, indent=2)
            
            print(f"✅ BACKUP 2: Archived to {local_backup_path} ({len(merged_local_backup)} total accounts)")
            
        except Exception as e:
            print(f"❌ BACKUP 2 failed: {e}")
        
        # Clean up temp file
        os.unlink(tmp_file_path)
        
        return success
        
    except Exception as e:
        logging.error(f"Save accounts error: {e}")
        return False
        
@app.route('/api/retrieve-users', methods=['POST'])
@login_required
def api_retrieve_users():
    try:
        result = google_api.retrieve_active_users()
        return jsonify(result)
    except Exception as e:
        logging.error(f"Retrieve users error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/load-suspended-users', methods=['POST'])
@login_required
def api_load_suspended_users():
    try:
        result = google_api.list_suspended_users()
        return jsonify(result)
    except Exception as e:
        logging.error(f"Load suspended users error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/retrieve-domains', methods=['POST'])
@login_required
def api_retrieve_domains():
    try:
        result = google_api.get_domains()
        
        if result.get('success'):
            # Mark domains as used if they're in our used list
            domains = result.get('domains', [])
            for domain in domains:
                domain_name = domain.get('domain_name')
                domain['is_used'] = domain_name in used_domains
                
            # Debug: print used domains
            print(f"DEBUG: Used domains: {list(used_domains)}")
            print(f"DEBUG: Retrieved domains with used status: {[(d['domain_name'], d.get('is_used', False)) for d in domains]}")
                
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"Retrieve domains error: {e}")
        return jsonify({"success": False, "error": str(e)})


@app.route('/api/refresh-accounts', methods=['POST'])
@login_required
def api_refresh_accounts():
    try:
        accounts = google_api.load_accounts_from_server()
        return jsonify({
            'success': True,
            'message': f'Loaded {len(accounts)} accounts',
            'accounts': list(accounts.keys())
        })
    except Exception as e:
        logging.error(f"Refresh accounts error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/clear-used-domains', methods=['POST'])
@login_required
def api_clear_used_domains():
    try:
        global used_domains
        used_domains.clear()
        
        if save_used_domains_to_server():
            print(f"DEBUG: Cleared all used domains and saved to SFTP")
            return jsonify({'success': True, 'message': 'All used domains cleared and saved to SFTP'})
        else:
            return jsonify({'success': True, 'message': 'Used domains cleared locally (SFTP save failed)'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


def test_smtp_credentials(credential_lines, recipient_email, smtp_server, smtp_port):
    """Test SMTP credentials"""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    
    results = []
    
    for i, credential_line in enumerate(credential_lines, 1):
        if ':' not in credential_line:
            results.append({
                'email': credential_line,
                'status': 'failed',
                'error': 'Invalid format (missing :)'
            })
            continue
        
        try:
            email, password = credential_line.split(':', 1)
            email = email.strip()
            password = password.strip()
            
            if not email or not password:
                results.append({
                    'email': email or 'Unknown',
                    'status': 'failed',
                    'error': 'Missing email or password'
                })
                continue
            
            # Test SMTP connection
            try:
                if smtp_port == 465:
                    smtp_conn = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=30)
                else:
                    smtp_conn = smtplib.SMTP(smtp_server, smtp_port, timeout=30)
                    smtp_conn.starttls()
                
                # Authenticate
                smtp_conn.login(email, password)
                
                # Send test email
                msg = MIMEMultipart()
                msg['From'] = email
                msg['To'] = recipient_email
                msg['Subject'] = f"SMTP Test from GBot Web ({email})"
                
                body = f"""
SMTP Test Email from GBot Web Application

Sender: {email}
Recipient: {recipient_email}
Server: {smtp_server}:{smtp_port}
Test Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This is an automated test email to verify SMTP credentials.
If you received this email, the SMTP configuration is working correctly.

---
GBot Web Application
                """.strip()
                
                msg.attach(MIMEText(body, 'plain'))
                
                smtp_conn.send_message(msg)
                smtp_conn.quit()
                
                results.append({
                    'email': email,
                    'status': 'success',
                    'message': 'Email sent successfully'
                })
                
            except smtplib.SMTPAuthenticationError as e:
                error_msg = "Authentication failed"
                error_str = str(e).lower()
                
                if "application-specific password required" in error_str:
                    error_msg = "App-specific password required"
                elif "username and password not accepted" in error_str:
                    error_msg = "Invalid username/password"
                elif "please log in via your web browser" in error_str:
                    error_msg = "Login via web browser required"
                
                results.append({
                    'email': email,
                    'status': 'failed',
                    'error': error_msg
                })
                
            except smtplib.SMTPConnectError:
                results.append({
                    'email': email,
                    'status': 'failed',
                    'error': f"Cannot connect to {smtp_server}:{smtp_port}"
                })
                
            except smtplib.SMTPServerDisconnected:
                results.append({
                    'email': email,
                    'status': 'failed',
                    'error': "Server disconnected unexpectedly"
                })
                
            except Exception as e:
                results.append({
                    'email': email,
                    'status': 'failed',
                    'error': f"SMTP error: {str(e)[:100]}"
                })
                
        except Exception as e:
            results.append({
                'email': credential_line.split(':')[0] if ':' in credential_line else credential_line,
                'status': 'failed',
                'error': f"Processing error: {str(e)[:100]}"
            })
    
    return results

def generate_user_csv(num_users, domain, password):
    """Generate CSV data for Google Workspace user import"""
    import csv
    import io
    from faker import Faker
    
    fake = Faker()
    
    # Google Workspace CSV headers
    headers = [
        "First Name [Required]",
        "Last Name [Required]", 
        "Email Address [Required]",
        "Password [Required]",
        "Password Hash Function [UPLOAD ONLY]",
        "Org Unit Path [Required]",
        "New Primary Email [UPLOAD ONLY]",
        "Recovery Email",
        "Home Secondary Email", 
        "Work Secondary Email",
        "Recovery Phone [MUST BE IN THE E.164 FORMAT]",
        "Work Phone",
        "Home Phone",
        "Mobile Phone",
        "Work Address",
        "Home Address",
        "Employee ID",
        "Employee Type",
        "Employee Title", 
        "Manager Email",
        "Department",
        "Cost Center",
        "Building ID",
        "Floor Name",
        "Floor Section",
        "Change Password at Next Sign-In",
        "New Status [UPLOAD ONLY]",
        "Advanced Protection Program enrollment"
    ]
    
    # Generate CSV data
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow(headers)
    
    # Generate users
    generated_emails = set()
    
    for i in range(num_users):
        first_name = fake.first_name()
        last_name = fake.last_name()
        
        # Generate unique email
        attempts = 0
        while attempts < 20:
            username = f"{first_name.lower()}.{last_name.lower()}{random.randint(1, 999)}"
            email = f"{username}@{domain}"
            
            if email not in generated_emails:
                generated_emails.add(email)
                break
            attempts += 1
        
        if attempts == 20:
            continue  # Skip if can't generate unique email
        
        # Create user row
        user_row = [
            first_name,                    # First Name [Required]
            last_name,                     # Last Name [Required] 
            email,                         # Email Address [Required]
            password,                      # Password [Required]
            "",                           # Password Hash Function [UPLOAD ONLY]
            "/",                          # Org Unit Path [Required]
            "",                           # New Primary Email [UPLOAD ONLY]
            "",                           # Recovery Email
            "",                           # Home Secondary Email
            "",                           # Work Secondary Email  
            "",                           # Recovery Phone [MUST BE IN THE E.164 FORMAT]
            "",                           # Work Phone
            "",                           # Home Phone
            "",                           # Mobile Phone
            "",                           # Work Address
            "",                           # Home Address
            "",                           # Employee ID
            "",                           # Employee Type
            "",                           # Employee Title
            "",                           # Manager Email
            "",                           # Department
            "",                           # Cost Center
            "",                           # Building ID
            "",                           # Floor Name
            "",                           # Floor Section
            "False",                      # Change Password at Next Sign-In
            "",                           # New Status [UPLOAD ONLY]
            "False"                       # Advanced Protection Program enrollment
        ]
        
        writer.writerow(user_row)
    
    csv_data = output.getvalue()
    output.close()
    
    return csv_data

def generate_domain_change_csv(users):
    """Generate CSV for domain changes - matching desktop app format"""
    import csv
    import io
    
    # Correct CSV headers to match desktop app
    headers = [
        "Current Email",
        "New Email", 
        "First Name",
        "Last Name",
        "Suspended"
    ]
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow(headers)
    
    # Write user data
    for user in users:
        current_email = user.get('email', '')
        first_name = user.get('first_name', '')
        last_name = user.get('last_name', '')
        suspended = "TRUE" if user.get('suspended', False) else "FALSE"
        
        # Leave new email same as current initially - user will modify this
        new_email = current_email
        
        writer.writerow([
            current_email,
            new_email,
            first_name, 
            last_name,
            suspended
        ])
    
    csv_data = output.getvalue()
    output.close()
    
    return csv_data

def update_user_domain_real(old_email, new_email):
    """Real domain update using Google API"""
    try:
        result = google_api.update_user_email(old_email, new_email)
        return result.get('success', False)
    except Exception as e:
        logging.error(f"Domain update error for {old_email}: {e}")
        return False
    
def process_single_user_domain_change(old_email):
    """Process domain change for a single user based on CSV logic"""
    # This would normally read from the CSV file
    # For now, we'll return the update using the global selected domain
    # You'd replace this with actual CSV parsing logic
    
    try:
        # In real implementation, you'd get new_email from CSV
        # For now, simulate the change
        return {"success": True, "new_email": old_email}  # Placeholder
        
    except Exception as e:
        return {"success": False, "error": str(e)}

def apply_domain_to_csv_data(users, selected_domain):
    """Apply selected domain to CSV data - matching desktop app format"""
    import csv
    import io
    
    # Correct headers to match desktop app
    headers = [
        "Current Email",
        "New Email", 
        "First Name",
        "Last Name",
        "Suspended"
    ]
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    
    for user in users:
        current_email = user.get('email', '')
        first_name = user.get('first_name', '')
        last_name = user.get('last_name', '')
        suspended = "TRUE" if user.get('suspended', False) else "FALSE"
        is_admin = user.get('admin', False)
        
        if is_admin:
            # Keep admin emails unchanged
            new_email = current_email
        else:
            # Apply new domain to non-admin users
            username = current_email.split('@')[0]
            new_email = f"{username}@{selected_domain}"
        
        writer.writerow([
            current_email,
            new_email,
            first_name,
            last_name,
            suspended
        ])
    
    csv_data = output.getvalue()
    output.close()
    return csv_data

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    print("=" * 50)
    print("🚀 GBot Web App Starting")
    print("📱 URL: http://localhost:3000")
    print("👤 Login: admin/admin123 or support/support123")
    print(f"🔗 Emergency access: /emergency-access/{WHITELIST_TOKEN}")
    print("=" * 50)
    
    app.run(debug=True, host='0.0.0.0', port=3000)