"""
DNS Manager Module for GBot Web App
Handles Namecheap API integration and Google Site Verification
"""

import os
import json
import xml.etree.ElementTree as ET
import requests
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode
import logging
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NamecheapAPI:
    """
    Namecheap API client for DNS record management
    """
    
    def with_username(self, username: str) -> 'NamecheapAPI':
        """Return a shallow copy with a different username (for fallback testing)."""
        copy = NamecheapAPI(
            api_user=self.api_user,
            api_key=self.api_key,
            username=username,
            client_ip=self.client_ip,
            sandbox=(self.base_url.endswith('sandbox.namecheap.com/xml.response'))
        )
        return copy
    
    def __init__(self, api_user: str, api_key: str, username: str, client_ip: str, 
                 sandbox: bool = False):
        """
        Initialize Namecheap API client
        
        Args:
            api_user: Namecheap API user
            api_key: Namecheap API key
            username: Namecheap username
            client_ip: Whitelisted client IP
            sandbox: Use sandbox environment for testing
        """
        self.api_user = api_user
        self.api_key = api_key
        self.username = username
        self.client_ip = client_ip
        
        if sandbox:
            self.base_url = "https://api.sandbox.namecheap.com/xml.response"
        else:
            self.base_url = "https://api.namecheap.com/xml.response"
        
        # Common parameters for all API calls
        self.common_params = {
            'ApiUser': self.api_user,
            'ApiKey': self.api_key,
            'UserName': self.username,
            'ClientIp': self.client_ip
        }
    
    def _make_request(self, command: str, params: Dict = None) -> ET.Element:
        """
        Make API request to Namecheap
        
        Args:
            command: API command to execute
            params: Additional parameters
            
        Returns:
            XML response as ElementTree.Element
            
        Raises:
            Exception: If API request fails
        """
        if params is None:
            params = {}
        
        # Combine common params with command-specific params
        all_params = {**self.common_params, 'Command': command, **params}
        
        try:
            response = requests.get(self.base_url, params=all_params, timeout=30)
            response.raise_for_status()
            
            # Parse XML response
            root = ET.fromstring(response.content)
            
            # Check for API errors
            status = root.get('Status')
            if status != 'OK':
                errors = root.findall('.//Error')
                if errors:
                    error_messages = [error.text for error in errors]
                    raise Exception(f"Namecheap API Error: {'; '.join(error_messages)}")
                else:
                    raise Exception(f"Namecheap API returned status: {status}")
            
            return root
            
        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP request failed: {str(e)}")
            raise Exception(f"Failed to connect to Namecheap API: {str(e)}")
        except ET.ParseError as e:
            logger.error(f"XML parsing failed: {str(e)}")
            raise Exception(f"Invalid XML response from Namecheap API: {str(e)}")
    
    def get_balance(self) -> Dict:
        """Check API authentication by calling users.getBalances"""
        try:
            root = self._make_request('namecheap.users.getBalances')
            result = root.find('.//UserGetBalancesResult')
            if result is None:
                raise Exception('Unexpected response from Namecheap: missing balances result')
            return {
                'success': True,
                'available_balance': result.get('AvailableBalance'),
                'account_balance': result.get('AccountBalance'),
                'earned_amount': result.get('EarnedAmount')
            }
        except Exception as e:
            logger.error(f"Balance check failed: {str(e)}")
            raise

    def get_domains(self, page: int = 1, page_size: int = 100, list_type: str = 'ALL', sort_by: str = 'NAME') -> List[str]:
        """
        Get all domains in the Namecheap account
        
        Returns:
            List of domain names as strings
        """
        try:
            params = {
                'Page': page,
                'PageSize': page_size,
                'ListType': list_type,
                'SortBy': sort_by
            }
            root = self._make_request('namecheap.domains.getList', params)
            domains = []
            for d in root.findall('.//Domain'):
                name = d.get('Name') or d.get('name')
                if name:
                    domains.append(name)
            return domains
        except Exception as e:
            logger.error(f"Failed to fetch domains: {str(e)}")
            raise

    def get_hosts(self, sld: str, tld: str) -> List[Dict]:
        """
        Get all DNS records for a domain
        
        Args:
            sld: Second Level Domain (e.g., 'example' from 'example.com')
            tld: Top Level Domain (e.g., 'com' from 'example.com')
            
        Returns:
            List of DNS records
        """
        try:
            params = {
                'SLD': sld,
                'TLD': tld
            }
            
            root = self._make_request('namecheap.domains.dns.getHosts', params)
            
            hosts = []
            for host in root.findall('.//host'):
                hosts.append({
                    'HostId': host.get('HostId'),
                    'Name': host.get('Name'),
                    'Type': host.get('Type'),
                    'Address': host.get('Address'),
                    'MXPref': host.get('MXPref'),
                    'TTL': host.get('TTL')
                })
            
            return hosts
            
        except Exception as e:
            logger.error(f"Failed to get hosts for {sld}.{tld}: {str(e)}")
            raise
    
    def set_hosts(self, sld: str, tld: str, hosts: List[Dict]) -> bool:
        """
        Set DNS records for a domain (replaces all records)
        
        Args:
            sld: Second Level Domain
            tld: Top Level Domain
            hosts: List of DNS records to set
            
        Returns:
            True if successful
        """
        try:
            params = {
                'SLD': sld,
                'TLD': tld
            }
            
            # Add host records to parameters
            for i, host in enumerate(hosts, 1):
                params[f'HostName{i}'] = host.get('Name', '@')
                params[f'RecordType{i}'] = host.get('Type', 'A')
                params[f'Address{i}'] = host.get('Address', '')
                
                if host.get('MXPref'):
                    params[f'MXPref{i}'] = host.get('MXPref')
                if host.get('TTL'):
                    params[f'TTL{i}'] = host.get('TTL')
            
            root = self._make_request('namecheap.domains.dns.setHosts', params)
            
            # Check if operation was successful
            result = root.find('.//DomainDNSSetHostsResult')
            if result is not None and result.get('IsSuccess') == 'true':
                return True
            else:
                raise Exception("setHosts operation failed")
                
        except Exception as e:
            logger.error(f"Failed to set hosts for {sld}.{tld}: {str(e)}")
            raise
    
    def add_or_update_record(self, domain: str, record_name: str, record_type: str, 
                           record_value: str, ttl: int = 1800, mx_pref: int = None) -> bool:
        """
        Add or update a single DNS record while preserving existing records
        
        Args:
            domain: Full domain name (e.g., 'example.com')
            record_name: Record name (e.g., 'www', '@' for root)
            record_type: Record type (A, CNAME, TXT, MX)
            record_value: Record value
            ttl: Time to live (default 1800)
            mx_pref: MX preference (only for MX records)
            
        Returns:
            True if successful
        """
        try:
            # Split domain into SLD and TLD
            sld, tld = self._split_domain(domain)
            
            # Get existing records
            existing_hosts = self.get_hosts(sld, tld)
            
            # Find if record already exists
            record_exists = False
            for i, host in enumerate(existing_hosts):
                if (host['Name'] == record_name and 
                    host['Type'].upper() == record_type.upper()):
                    # Update existing record
                    existing_hosts[i] = {
                        'Name': record_name,
                        'Type': record_type,
                        'Address': record_value,
                        'TTL': str(ttl),
                        'MXPref': str(mx_pref) if mx_pref else None
                    }
                    record_exists = True
                    break
            
            # Add new record if it doesn't exist
            if not record_exists:
                new_record = {
                    'Name': record_name,
                    'Type': record_type,
                    'Address': record_value,
                    'TTL': str(ttl)
                }
                if mx_pref:
                    new_record['MXPref'] = str(mx_pref)
                
                existing_hosts.append(new_record)
            
            # Set all hosts (existing + new/updated)
            return self.set_hosts(sld, tld, existing_hosts)
            
        except Exception as e:
            logger.error(f"Failed to add/update record {record_name} for {domain}: {str(e)}")
            raise
    
    def delete_record(self, domain: str, record_name: str, record_type: str = None) -> bool:
        """
        Delete a DNS record while preserving other records
        
        Args:
            domain: Full domain name
            record_name: Record name to delete
            record_type: Record type (optional, if None deletes all records with the name)
            
        Returns:
            True if successful
        """
        try:
            # Split domain into SLD and TLD
            sld, tld = self._split_domain(domain)
            
            # Get existing records
            existing_hosts = self.get_hosts(sld, tld)
            
            # Filter out records to delete
            filtered_hosts = []
            for host in existing_hosts:
                if host['Name'] == record_name:
                    if record_type is None or host['Type'].upper() == record_type.upper():
                        # Skip this record (delete it)
                        continue
                filtered_hosts.append(host)
            
            # Set filtered hosts
            return self.set_hosts(sld, tld, filtered_hosts)
            
        except Exception as e:
            logger.error(f"Failed to delete record {record_name} for {domain}: {str(e)}")
            raise
    
    def create_subdomain(self, domain: str, subdomain: str, target_ip: str, 
                        record_type: str = 'A', ttl: int = 1800) -> bool:
        """
        Create a subdomain record
        
        Args:
            domain: Parent domain (e.g., 'example.com')
            subdomain: Subdomain name (e.g., 'api')
            target_ip: Target IP address or CNAME target
            record_type: Record type (A or CNAME)
            ttl: Time to live
            
        Returns:
            True if successful
        """
        return self.add_or_update_record(domain, subdomain, record_type, target_ip, ttl)
    
    def _split_domain(self, domain: str) -> Tuple[str, str]:
        """
        Split domain into SLD and TLD
        
        Args:
            domain: Full domain name (e.g., 'example.com')
            
        Returns:
            Tuple of (SLD, TLD)
        """
        parts = domain.split('.')
        if len(parts) < 2:
            raise ValueError(f"Invalid domain format: {domain}")
        
        # Handle common TLDs
        if len(parts) == 2:
            return parts[0], parts[1]
        elif len(parts) == 3 and parts[1] in ['co', 'com', 'org', 'net', 'gov', 'edu']:
            # Handle domains like example.co.uk
            return parts[0], '.'.join(parts[1:])
        else:
            # Default: treat last part as TLD
            return '.'.join(parts[:-1]), parts[-1]


class GoogleSiteVerification:
    """
    Google Site Verification API client
    """
    
    def __init__(self, credentials_path: str = None, credentials_json: Dict = None):
        """
        Initialize Google Site Verification client
        
        Args:
            credentials_path: Path to service account JSON file
            credentials_json: Service account credentials as dict
        """
        self.credentials_path = credentials_path
        self.credentials_json = credentials_json
        self.service = None
        self._initialize_service()
    
    def _initialize_service(self):
        """Initialize Google Site Verification service"""
        try:
            if self.credentials_json:
                # Use service account credentials from dict
                from google.oauth2 import service_account
                
                credentials = service_account.Credentials.from_service_account_info(
                    self.credentials_json,
                    scopes=['https://www.googleapis.com/auth/siteverification']
                )
            elif self.credentials_path and os.path.exists(self.credentials_path):
                # Use service account credentials from file
                from google.oauth2 import service_account
                
                credentials = service_account.Credentials.from_service_account_file(
                    self.credentials_path,
                    scopes=['https://www.googleapis.com/auth/siteverification']
                )
            else:
                raise Exception("No valid Google credentials provided")
            
            self.service = build('siteverification', 'v1', credentials=credentials)
            
        except Exception as e:
            logger.error(f"Failed to initialize Google Site Verification service: {str(e)}")
            raise
    
    def get_verification_token(self, domain: str, verification_method: str = 'DNS_TXT') -> str:
        """
        Get verification token for domain
        
        Args:
            domain: Domain to verify
            verification_method: Verification method (DNS_TXT, DNS_CNAME, etc.)
            
        Returns:
            Verification token string
        """
        try:
            request_body = {
                'site': {
                    'type': 'SITE',
                    'identifier': f'http://{domain}'
                },
                'verificationMethod': verification_method
            }
            
            result = self.service.webResource().getToken(body=request_body).execute()
            return result.get('token', '')
            
        except Exception as e:
            logger.error(f"Failed to get verification token for {domain}: {str(e)}")
            raise
    
    def verify_domain(self, domain: str, verification_method: str = 'DNS_TXT') -> bool:
        """
        Verify domain ownership
        
        Args:
            domain: Domain to verify
            verification_method: Verification method
            
        Returns:
            True if verification successful
        """
        try:
            request_body = {
                'site': {
                    'type': 'SITE',
                    'identifier': f'http://{domain}'
                },
                'verificationMethod': verification_method
            }
            
            result = self.service.webResource().insert(body=request_body).execute()
            return result.get('id') is not None
            
        except Exception as e:
            logger.error(f"Failed to verify domain {domain}: {str(e)}")
            raise
    
    def list_verified_sites(self) -> List[Dict]:
        """
        List all verified sites
        
        Returns:
            List of verified sites
        """
        try:
            result = self.service.webResource().list().execute()
            return result.get('items', [])
            
        except Exception as e:
            logger.error(f"Failed to list verified sites: {str(e)}")
            raise


class DNSManager:
    """
    Main DNS management class combining Namecheap and Google Site Verification
    """
    
    def __init__(self, namecheap_config: Dict, google_config: Dict = None):
        """
        Initialize DNS Manager
        
        Args:
            namecheap_config: Namecheap API configuration
            google_config: Google API configuration (optional)
        """
        self.namecheap = NamecheapAPI(**namecheap_config)
        
        if google_config:
            self.google_verification = GoogleSiteVerification(**google_config)
        else:
            self.google_verification = None
    
    def create_subdomain_with_records(self, domain: str, subdomain: str, 
                                    target_ip: str, additional_records: List[Dict] = None) -> Dict:
        """
        Create subdomain with optional additional DNS records
        
        Args:
            domain: Parent domain
            subdomain: Subdomain name
            target_ip: Target IP for A record
            additional_records: Additional DNS records to create
            
        Returns:
            Result dictionary with success status and details
        """
        try:
            results = {
                'success': True,
                'subdomain_created': False,
                'additional_records': [],
                'errors': []
            }
            
            # Create main subdomain A record
            try:
                self.namecheap.create_subdomain(domain, subdomain, target_ip)
                results['subdomain_created'] = True
                logger.info(f"Created subdomain {subdomain}.{domain} -> {target_ip}")
            except Exception as e:
                results['success'] = False
                results['errors'].append(f"Failed to create subdomain: {str(e)}")
            
            # Create additional records if provided
            if additional_records:
                for record in additional_records:
                    try:
                        self.namecheap.add_or_update_record(
                            domain,
                            record.get('name', '@'),
                            record.get('type', 'A'),
                            record.get('value', ''),
                            record.get('ttl', 1800),
                            record.get('mx_pref')
                        )
                        results['additional_records'].append({
                            'name': record.get('name'),
                            'type': record.get('type'),
                            'success': True
                        })
                        logger.info(f"Created additional record: {record}")
                    except Exception as e:
                        results['success'] = False
                        error_msg = f"Failed to create record {record.get('name', 'unknown')}: {str(e)}"
                        results['errors'].append(error_msg)
                        results['additional_records'].append({
                            'name': record.get('name'),
                            'type': record.get('type'),
                            'success': False,
                            'error': str(e)
                        })
            
            return results
            
        except Exception as e:
            logger.error(f"DNS Manager error: {str(e)}")
            return {
                'success': False,
                'subdomain_created': False,
                'additional_records': [],
                'errors': [f"DNS Manager error: {str(e)}"]
            }
    
    def verify_domain_with_google(self, domain: str) -> Dict:
        """
        Complete Google Site Verification workflow
        
        Args:
            domain: Domain to verify
            
        Returns:
            Result dictionary with verification details
        """
        try:
            if not self.google_verification:
                return {
                    'success': False,
                    'error': 'Google Site Verification not configured'
                }
            
            # Step 1: Get verification token
            token = self.google_verification.get_verification_token(domain)
            if not token:
                return {
                    'success': False,
                    'error': 'Failed to get verification token'
                }
            
            # Step 2: Add TXT record to DNS
            try:
                self.namecheap.add_or_update_record(
                    domain, 
                    '@', 
                    'TXT', 
                    token,
                    300  # Short TTL for verification
                )
                logger.info(f"Added TXT verification record for {domain}")
            except Exception as e:
                return {
                    'success': False,
                    'error': f'Failed to add TXT record: {str(e)}'
                }
            
            # Step 3: Wait for DNS propagation
            time.sleep(10)
            
            # Step 4: Verify domain
            try:
                verified = self.google_verification.verify_domain(domain)
                if verified:
                    return {
                        'success': True,
                        'domain': domain,
                        'verification_token': token,
                        'message': 'Domain successfully verified with Google'
                    }
                else:
                    return {
                        'success': False,
                        'error': 'Domain verification failed'
                    }
            except Exception as e:
                return {
                    'success': False,
                    'error': f'Verification failed: {str(e)}'
                }
                
        except Exception as e:
            logger.error(f"Google verification error: {str(e)}")
            return {
                'success': False,
                'error': f'Google verification error: {str(e)}'
            }
    
    def get_domain_records(self, domain: str) -> Dict:
        """
        Get all DNS records for a domain
        
        Args:
            domain: Domain name
            
        Returns:
            Dictionary with domain records
        """
        try:
            sld, tld = self.namecheap._split_domain(domain)
            hosts = self.namecheap.get_hosts(sld, tld)
            
            return {
                'success': True,
                'domain': domain,
                'records': hosts
            }
            
        except Exception as e:
            logger.error(f"Failed to get records for {domain}: {str(e)}")
            return {
                'success': False,
                'error': f'Failed to get records: {str(e)}'
            }

    def get_domains(self) -> Dict:
        """Fetch domains list from Namecheap account"""
        try:
            domains = self.namecheap.get_domains(page=1, page_size=100)
            return {'success': True, 'domains': domains}
        except Exception as e:
            logger.error(f"Failed to get domains list: {str(e)}")
            return {'success': False, 'error': str(e)}