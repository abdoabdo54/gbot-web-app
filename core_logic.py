# Your Google API & SFTP functions
import os
import json
import logging
import time
import paramiko
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import google.auth.transport.requests
from config import *

class WebGoogleAPI:
    def __init__(self):
        self.service = None
        self.current_account_name = None
        self.authenticated_accounts = set()
    
    def load_accounts_from_server(self):
        """Load accounts.json from SFTP server"""
        for remote_path in [f"{REMOTE_DIR}accounts.json", f"{REMOTE_ALT_DIR}accounts.json"]:
            try:
                transport = paramiko.Transport((SERVER_ADDRESS, SERVER_PORT))
                transport.connect(username=USERNAME, password=PASSWORD)
                sftp = paramiko.SFTPClient.from_transport(transport)
                
                with sftp.open(remote_path, 'r') as f:
                    content = f.read()
                
                sftp.close()
                transport.close()
                
                if content.strip():
                    return json.loads(content)
            except Exception as e:
                logging.warning(f"Failed to load from {remote_path}: {e}")
                continue
        return {}
    
    def load_tokens_from_server(self):
        """Load tokens.json from SFTP server"""
        for remote_path in [f"{REMOTE_DIR}tokens.json", f"{REMOTE_ALT_DIR}tokens.json"]:
            try:
                transport = paramiko.Transport((SERVER_ADDRESS, SERVER_PORT))
                transport.connect(username=USERNAME, password=PASSWORD)
                sftp = paramiko.SFTPClient.from_transport(transport)
                
                with sftp.open(remote_path, 'r') as f:
                    content = f.read()
                
                sftp.close()
                transport.close()
                
                if content.strip():
                    return json.loads(content)
            except Exception as e:
                logging.warning(f"Failed to load tokens from {remote_path}: {e}")
                continue
        return {}
    
    def has_valid_tokens(self, account_name):
        """Check if account has valid tokens"""
        try:
            tokens = self.load_tokens_from_server()
            if account_name not in tokens:
                return False
            
            data = tokens[account_name]
            required = ['token', 'refresh_token', 'token_uri', 'client_id', 'client_secret']
            
            if not all(k in data for k in required):
                return False
            
            creds = Credentials(
                token=data['token'],
                refresh_token=data['refresh_token'],
                token_uri=data['token_uri'],
                client_id=data['client_id'],
                client_secret=data['client_secret'],
                scopes=data.get('scopes', SCOPES)
            )
            
            if creds.valid:
                return True
            elif creds.expired and creds.refresh_token:
                creds.refresh(google.auth.transport.requests.Request())
                return creds.valid
            
            return False
        except Exception as e:
            logging.error(f"Error checking tokens for {account_name}: {e}")
            return False
    
    def authenticate_with_tokens(self, account_name):
        """Authenticate using existing tokens"""
        try:
            tokens = self.load_tokens_from_server()
            if account_name not in tokens:
                return False
            
            data = tokens[account_name]
            creds = Credentials(
                token=data['token'],
                refresh_token=data['refresh_token'],
                token_uri=data['token_uri'],
                client_id=data['client_id'],
                client_secret=data['client_secret'],
                scopes=data.get('scopes', SCOPES)
            )
            
            if creds.expired and creds.refresh_token:
                creds.refresh(google.auth.transport.requests.Request())
            
            if creds.valid:
                self.service = build('admin', 'directory_v1', credentials=creds)
                self.current_account_name = account_name
                self.authenticated_accounts.add(account_name)
                return True
            
            return False
        except Exception as e:
            logging.error(f"Token authentication failed for {account_name}: {e}")
            return False
    
    def get_oauth_url(self, account_name, accounts_data):
        """Generate OAuth URL for manual authentication"""
        try:
            creds = accounts_data[account_name]
            flow_config = {
                "installed": {
                    "client_id": creds['client_id'],
                    "client_secret": creds['client_secret'],
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                    "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"]
                }
            }
            
            flow = InstalledAppFlow.from_client_config(flow_config, SCOPES)
            auth_url, _ = flow.authorization_url(prompt='consent')
            return auth_url
        except Exception as e:
            logging.error(f"Failed to generate OAuth URL: {e}")
            return None
    
    def retrieve_active_users(self):
        """Get all users from Google Workspace"""
        if not self.service:
            return {"error": "Not authenticated"}
        
        try:
            all_users = []
            page_token = None
            
            while True:
                results = self.service.users().list(
                    customer='my_customer',
                    orderBy='email',
                    maxResults=500,
                    projection='full',
                    fields='nextPageToken,users(primaryEmail,name/givenName,name/familyName,suspended,isAdmin)',
                    pageToken=page_token
                ).execute()
                
                users_in_page = results.get('users', [])
                all_users.extend(users_in_page)
                
                page_token = results.get('nextPageToken')
                if not page_token:
                    break
            
            processed_users = []
            for user in all_users:
                processed_users.append({
                    'email': user.get('primaryEmail', 'N/A'),
                    'first_name': user.get('name', {}).get('givenName', ''),
                    'last_name': user.get('name', {}).get('familyName', ''),
                    'suspended': user.get('suspended', False),
                    'admin': user.get('isAdmin', False)
                })
            
            return {
                "success": True,
                "users": processed_users,
                "total_count": len(processed_users)
            }
            
        except HttpError as error:
            logging.error(f"API error retrieving users: {error}")
            return {"error": f"API Error: {error}"}
        except Exception as e:
            logging.error(f"Unexpected error retrieving users: {e}")
            return {"error": f"Error: {e}"}
    
    def list_suspended_users(self):
        """Get suspended users"""
        if not self.service:
            return {"error": "Not authenticated"}
        
        try:
            suspended_users = []
            page_token = None
            
            while True:
                results = self.service.users().list(
                    customer='my_customer',
                    query='isSuspended=true',
                    maxResults=500,
                    projection='basic',
                    orderBy='email',
                    pageToken=page_token
                ).execute()
                
                users = results.get('users', [])
                suspended_users.extend(users)
                
                page_token = results.get('nextPageToken')
                if not page_token:
                    break
            
            user_emails = [user.get('primaryEmail') for user in suspended_users]
            return {"success": True, "users": user_emails}
            
        except Exception as e:
            logging.error(f"Error listing suspended users: {e}")
            return {"error": f"Error: {e}"}
    
    def get_domains(self):
        """Get verified domains"""
        if not self.service:
            return {"error": "Not authenticated"}
        
        try:
            domain_results = self.service.domains().list(customer='my_customer').execute()
            domains = domain_results.get('domains', [])
            
            verified_domains = [d for d in domains if d.get('verified')]
            
            domain_info = []
            for domain in verified_domains:
                domain_info.append({
                    'domain_name': domain.get('domainName'),
                    'verified': True,
                    'user_count': 0  # You can add user counting logic here
                })
            
            return {"success": True, "domains": domain_info}
            
        except Exception as e:
            logging.error(f"Error getting domains: {e}")
            return {"error": f"Error: {e}"}

    def create_user(self, user_info):
        """Create a single user"""
        if not self.service:
            return {"success": False, "error": "Not authenticated"}
        
        try:
            result = self.service.users().insert(body=user_info).execute()
            email = result.get('primaryEmail')
            logging.info(f"User created: {email}")
            return {"success": True, "email": email}
            
        except HttpError as error:
            error_content = error.content.decode('utf-8') if error.content else str(error)
            logging.error(f"User creation failed: {error_content}")
            return {"success": False, "error": f"Creation failed: {error.resp.status}"}
        except Exception as e:
            logging.error(f"Unexpected error creating user: {e}")
            return {"success": False, "error": str(e)}
    
    def delete_user(self, user_email):
        """Delete a user"""
        if not self.service:
            return {"success": False, "error": "Not authenticated"}
        
        try:
            self.service.users().delete(userKey=user_email).execute()
            logging.info(f"User deleted: {user_email}")
            return {"success": True}
            
        except HttpError as error:
            if error.resp.status == 404:
                return {"success": True, "message": "User not found (already deleted?)"}
            
            error_content = error.content.decode('utf-8') if error.content else str(error)
            logging.error(f"User deletion failed: {error_content}")
            return {"success": False, "error": f"Deletion failed: {error.resp.status}"}
        except Exception as e:
            logging.error(f"Unexpected error deleting user: {e}")
            return {"success": False, "error": str(e)}
            
    def update_user_email(self, old_email, new_email):
        """Update user's primary email address"""
        if not self.service:
            return {"success": False, "error": "Not authenticated"}
        
        # Skip if emails are the same
        if old_email == new_email:
            return {"success": True, "old_email": old_email, "new_email": new_email, "message": "No change needed"}
        
        try:
            # First check if user exists with old email
            try:
                user = self.service.users().get(userKey=old_email).execute()
            except HttpError as e:
                if e.resp.status == 404:
                    return {"success": False, "error": f"User {old_email} not found"}
                raise
            
            # Check if new email already exists
            try:
                existing_user = self.service.users().get(userKey=new_email).execute()
                if existing_user:
                    return {"success": False, "error": f"User with email {new_email} already exists"}
            except HttpError as e:
                if e.resp.status != 404:  # 404 is good - means new email doesn't exist
                    raise
            
            # Update the primary email
            user_update = {
                'primaryEmail': new_email
            }
            
            # Update the user
            result = self.service.users().update(
                userKey=old_email, 
                body=user_update
            ).execute()
            
            logging.info(f"User email updated: {old_email} → {new_email}")
            return {"success": True, "old_email": old_email, "new_email": new_email}
            
        except HttpError as error:
            error_content = error.content.decode('utf-8') if error.content else str(error)
            logging.error(f"Email update failed for {old_email}: {error_content}")
            return {"success": False, "error": f"Update failed: {error.resp.status} - {error.resp.reason}"}
        except Exception as e:
            logging.error(f"Unexpected error updating email for {old_email}: {e}")
            return {"success": False, "error": str(e)}

# Global instance
google_api = WebGoogleAPI()