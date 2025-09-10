import os
import json
import logging
import uuid
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import google.auth.transport.requests
from flask import session
from database import db, GoogleAccount, GoogleToken

# Use a more robust session service storage
_session_services = {}

class WebGoogleAPI:
    def get_credentials(self, account_name):
        account = GoogleAccount.query.filter_by(account_name=account_name).first()
        if not account or not account.tokens:
            return None
        
        token = account.tokens[0]
        scopes = [scope.name for scope in token.scopes]
        
        return Credentials(
            token=token.token,
            refresh_token=token.refresh_token,
            token_uri=token.token_uri,
            client_id=account.client_id,
            client_secret=account.client_secret,
            scopes=scopes
        )

    def has_valid_tokens(self, account_name):
        creds = self.get_credentials(account_name)
        if not creds:
            return False
        return creds.valid

    def is_token_valid(self, account_name):
        """Alias for has_valid_tokens for backward compatibility"""
        return self.has_valid_tokens(account_name)

    def authenticate_with_tokens(self, account_name):
        creds = self.get_credentials(account_name)
        if not creds:
            return False

        if creds.expired and creds.refresh_token:
            creds.refresh(google.auth.transport.requests.Request())

        if creds.valid:
            service = build('admin', 'directory_v1', credentials=creds)
            self._set_current_service(account_name, service)
            return True
        return False

    def get_oauth_url(self, account_name, creds_data):
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
        flow = InstalledAppFlow.from_client_config(flow_config, scopes=[
            'https://www.googleapis.com/auth/admin.directory.user',
            'https://www.googleapis.com/auth/admin.directory.domain'
        ])
        flow.redirect_uri = "https://g-workspace.ecochain.site/oauth-callback"
        auth_url, state = flow.authorization_url(
            access_type='offline',
            prompt='consent',
            include_granted_scopes='true'
        )
        return auth_url

    def _get_session_id(self):
        if 'session_id' not in session:
            session['session_id'] = str(uuid.uuid4())
        return session['session_id']

    def _get_session_key(self, account_name):
        session_id = self._get_session_id()
        return f"{session_id}_{account_name}"

    def _get_current_service(self):
        current_account = session.get('current_account_name')
        if not current_account:
            logging.warning("No current account in session")
            return None
        
        service_key = self._get_session_key(current_account)
        service = _session_services.get(service_key)
        
        if service is None:
            logging.info(f"No service found for account {current_account}, attempting to recreate...")
            # Try to recreate the service if it doesn't exist
            if self.is_token_valid(current_account):
                success = self.authenticate_with_tokens(current_account)
                if success:
                    service = _session_services.get(service_key)
                    logging.info(f"Successfully recreated service for account {current_account}")
                else:
                    logging.error(f"Failed to recreate service for account {current_account}")
            else:
                logging.error(f"No valid tokens for account {current_account}")
        
        return service

    def _set_current_service(self, account_name, service):
        service_key = self._get_session_key(account_name)
        _session_services[service_key] = service
        session['current_account_name'] = account_name
        logging.info(f"Service set for account {account_name} with key {service_key}")

    @property
    def service(self):
        return self._get_current_service()
    
    def clear_invalid_services(self):
        """Clear any invalid or expired services from the session storage"""
        current_account = session.get('current_account_name')
        if current_account:
            service_key = self._get_session_key(current_account)
            if service_key in _session_services:
                del _session_services[service_key]
                logging.info(f"Cleared invalid service for account {current_account}")
    
    def validate_and_recreate_service(self, account_name):
        """Validate current service and recreate if necessary"""
        if not account_name:
            return False
            
        # Check if we have a valid service
        service = self._get_current_service()
        if service is not None:
            return True
            
        # Try to recreate the service
        if self.is_token_valid(account_name):
            success = self.authenticate_with_tokens(account_name)
            if success:
                logging.info(f"Successfully recreated service for account {account_name}")
                return True
            else:
                logging.error(f"Failed to recreate service for account {account_name}")
                return False
        else:
            logging.error(f"No valid tokens for account {account_name}")
            return False

    def create_gsuite_user(self, first_name, last_name, email, password):
        if not self.service:
            raise Exception("Not authenticated or session expired.")
        
        user_body = {
            "primaryEmail": email,
            "name": {
                "givenName": first_name,
                "familyName": last_name
            },
            "password": password,
            "changePasswordAtNextLogin": False
        }
        
        try:
            user = self.service.users().insert(body=user_body).execute()
            return {"success": True, "user": user}
        except HttpError as e:
            return {"success": False, "error": str(e)}

    def get_domain_info(self):
        if not self.service:
            raise Exception("Not authenticated or session expired.")
        
        try:
            domains = self.service.domains().list(customer="my_customer").execute()
            return {"success": True, "domains": domains.get("domains", [])}
        except HttpError as e:
            return {"success": False, "error": str(e)}

    def add_domain_alias(self, domain_alias):
        if not self.service:
            raise Exception("Not authenticated or session expired.")
        
        domain_body = {
            "domainName": domain_alias
        }
        
        try:
            domain = self.service.domains().insert(customer="my_customer", body=domain_body).execute()
            return {"success": True, "domain": domain}
        except HttpError as e:
            return {"success": False, "error": str(e)}

    def delete_domain(self, domain_name):
        if not self.service:
            raise Exception("Not authenticated or session expired.")
        
        try:
            self.service.domains().delete(customer="my_customer", domainName=domain_name).execute()
            return {"success": True, "message": f"Domain {domain_name} deleted successfully."}
        except HttpError as e:
            return {"success": False, "error": str(e)}

    def get_users(self, max_results=500):
        """Retrieve all users from the authenticated Google account"""
        if not self.service:
            raise Exception("Not authenticated or session expired.")
        
        try:
            users_result = self.service.users().list(customer='my_customer', maxResults=max_results).execute()
            return {"success": True, "users": users_result.get("users", [])}
        except HttpError as e:
            return {"success": False, "error": str(e)}

google_api = WebGoogleAPI()
