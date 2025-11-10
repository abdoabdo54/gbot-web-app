"""
DNS Manager Module for GBot Web App
Production-ready Namecheap API integration and Google Site Verification
"""

import os
import json
import xml.etree.ElementTree as ET
import requests
import time
import logging
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlencode
from googleapiclient.discovery import build
from google.oauth2 import service_account
from google.auth.transport.requests import Request

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NamecheapError(Exception):
    """Custom exception for Namecheap API errors"""
    def __init__(self, message: str, error_code: str = None):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)


class NamecheapAPI:
    """
    Production-ready Namecheap API client for DNS record management
    """
    
    def __init__(self, api_user: str, api_key: str, username: str, client_ip: str, 
                 sandbox: bool = False):
        """
        Initialize Namecheap API client
        
        Args:
            api_user: Namecheap API user
            api_key: Namecheap API key  
            username: Namecheap username
            client_ip: Whitelisted client IP
            sandbox: Use sandbox environment (default: False for production)
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
        
        logger.info(f"Initialized Namecheap API client for user: {self.username}")
    
    def _make_request(self, command: str, params: Dict = None) -> ET.Element:
        """
        Make authenticated API request to Namecheap
        
        Args:
            command: API command to execute
            params: Additional parameters for the command
            
        Returns:
            XML response as ElementTree.Element
            
        Raises:
            NamecheapError: If API request fails or returns error
        """
        if params is None:
            params = {}
        
        # Combine common params with command-specific params
        all_params = {**self.common_params, 'Command': command, **params}
        
        logger.debug(f"Making Namecheap API request: {command}")
        
        try:
            response = requests.get(self.base_url, params=all_params, timeout=30)
            response.raise_for_status()
            
            # Parse XML response
            try:
                root = ET.fromstring(response.content)
            except ET.ParseError as e:
                raise NamecheapError(f"Invalid XML response: {str(e)}")
            
            # Check API status
            status = root.get('Status')
            if status != 'OK':
                errors = root.findall('.//Error')
                if errors:
                    error_messages = []
                    for error in errors:
                        error_code = error.get('Number', 'Unknown')
                        error_text = error.text or 'No error message'
                        error_messages.append(f"#{error_code}: {error_text}")
                    
                    error_msg = '; '.join(error_messages)
                    raise NamecheapError(error_msg, error_code)
                else:
                    raise NamecheapError(f"API returned status: {status}")
            
            return root
            
        except requests.exceptions.RequestException as e:
            raise NamecheapError(f"HTTP request failed: {str(e)}")
        except Exception as e:
            if isinstance(e, NamecheapError):
                raise
            raise NamecheapError(f"Unexpected error: {str(e)}")
    
    def test_connection(self) -> Dict:
        """
        Test API connection and authentication
        
        Returns:
            Dict with test results
        """
        try:
            # Use domain check as a simple test
            root = self._make_request('namecheap.domains.check', {'DomainList': 'google.com'})
            
            results = root.findall('.//DomainCheckResult')
            return {
                'success': True,
                'message': 'Connection successful',
                'test_domains': len(results)
            }
            
        except NamecheapError as e:
            return {
                'success': False,
                'error': str(e),
                'error_code': e.error_code
            }
    
    def get_domains_list(self, page: int = 1, page_size: int = 100) -> List[str]:
        """
        Get list of domains in account
        
        Args:
            page: Page number (default: 1)
            page_size: Items per page (default: 100)
            
        Returns:
            List of domain names
        """
        try:
            params = {
                'Page': page,
                'PageSize': page_size,
                'ListType': 'ALL',
                'SortBy': 'NAME'
            }
            
            root = self._make_request('namecheap.domains.getList', params)
            
            domains = []
            for domain_elem in root.findall('.//Domain'):
                domain_name = domain_elem.get('Name')
                if domain_name:
                    domains.append(domain_name)
            
            logger.info(f"Retrieved {len(domains)} domains from account")
            return domains
            
        except NamecheapError as e:
            logger.error(f"Failed to get domains list: {str(e)}")
            raise
    
    def get_host_records(self, domain: str) -> List[Dict]:
        """
        Get DNS host records for a domain
        
        Args:
            domain: Domain name (e.g., 'example.com')
            
        Returns:
            List of DNS record dictionaries
        """
        try:
            sld, tld = self._split_domain(domain)
            
            params = {
                'SLD': sld,
                'TLD': tld
            }
            
            root = self._make_request('namecheap.domains.dns.getHosts', params)
            
            records = []
            for host in root.findall('.//host'):
                record = {
                    'HostId': host.get('HostId'),
                    'Name': host.get('Name', '@'),
                    'Type': host.get('Type'),
                    'Address': host.get('Address'),
                    'MXPref': host.get('MXPref'),
                    'TTL': host.get('TTL', '1800'),
                    'AssociatedAppTitle': host.get('AssociatedAppTitle'),
                    'FriendlyName': host.get('FriendlyName')
                }
                records.append(record)
            
            logger.info(f"Retrieved {len(records)} DNS records for {domain}")
            return records
            
        except NamecheapError as e:
            logger.error(f"Failed to get host records for {domain}: {str(e)}")
            raise
    
    def set_host_records(self, domain: str, records: List[Dict]) -> bool:
        """
        Set DNS host records for a domain (replaces all existing records)
        
        Args:
            domain: Domain name
            records: List of DNS record dictionaries
            
        Returns:
            True if successful
        """
        try:
            sld, tld = self._split_domain(domain)
            
            params = {
                'SLD': sld,
                'TLD': tld
            }
            
            # Add host records to parameters
            for i, record in enumerate(records, 1):
                params[f'HostName{i}'] = record.get('Name', '@')
                params[f'RecordType{i}'] = record.get('Type', 'A')
                params[f'Address{i}'] = record.get('Address', '')
                
                if record.get('TTL'):
                    params[f'TTL{i}'] = str(record.get('TTL'))
                
                if record.get('MXPref') and record.get('Type') == 'MX':
                    params[f'MXPref{i}'] = str(record.get('MXPref'))
            
            root = self._make_request('namecheap.domains.dns.setHosts', params)
            
            # Check result
            result = root.find('.//DomainDNSSetHostsResult')
            if result is not None and result.get('IsSuccess') == 'true':
                logger.info(f"Successfully updated DNS records for {domain}")
                return True
            else:
                raise NamecheapError("setHosts operation failed")
                
        except NamecheapError as e:
            logger.error(f"Failed to set host records for {domain}: {str(e)}")
            raise
    
    def add_record(self, domain: str, name: str, record_type: str, value: str, 
                   ttl: int = 1800, mx_pref: int = None, preserve_existing: bool = True) -> bool:
        """
        Add or update a DNS record while optionally preserving existing records
        
        Args:
            domain: Domain name
            name: Record name (use '@' for root domain)
            record_type: Record type (A, CNAME, TXT, MX)
            value: Record value
            ttl: Time to live in seconds
            mx_pref: MX preference (only for MX records)
            preserve_existing: Whether to preserve other existing records
            
        Returns:
            True if successful
        """
        try:
            if preserve_existing:
                # Get existing records
                existing_records = self.get_host_records(domain)
                
                # Check if record already exists and update it
                record_updated = False
                for i, record in enumerate(existing_records):
                    if (record['Name'] == name and 
                        record['Type'].upper() == record_type.upper()):
                        existing_records[i].update({
                            'Address': value,
                            'TTL': str(ttl)
                        })
                        if mx_pref and record_type.upper() == 'MX':
                            existing_records[i]['MXPref'] = str(mx_pref)
                        record_updated = True
                        break
                
                # Add new record if it doesn't exist
                if not record_updated:
                    new_record = {
                        'Name': name,
                        'Type': record_type,
                        'Address': value,
                        'TTL': str(ttl)
                    }
                    if mx_pref and record_type.upper() == 'MX':
                        new_record['MXPref'] = str(mx_pref)
                    
                    existing_records.append(new_record)
                
                # Set all records
                return self.set_host_records(domain, existing_records)
            else:
                # Create single record
                record = {
                    'Name': name,
                    'Type': record_type,
                    'Address': value,
                    'TTL': str(ttl)
                }
                if mx_pref and record_type.upper() == 'MX':
                    record['MXPref'] = str(mx_pref)
                
                return self.set_host_records(domain, [record])
                
        except NamecheapError as e:
            logger.error(f"Failed to add record {name}.{domain}: {str(e)}")
            raise
    
    def delete_record(self, domain: str, name: str, record_type: str = None) -> bool:
        """
        Delete a DNS record while preserving other records
        
        Args:
            domain: Domain name
            name: Record name to delete
            record_type: Record type (optional filter)
            
        Returns:
            True if successful
        """
        try:
            existing_records = self.get_host_records(domain)
            
            # Filter out records to delete
            filtered_records = []
            for record in existing_records:
                if record['Name'] == name:
                    if record_type is None or record['Type'].upper() == record_type.upper():
                        continue  # Skip this record (delete it)
                filtered_records.append(record)
            
            return self.set_host_records(domain, filtered_records)
            
        except NamecheapError as e:
            logger.error(f"Failed to delete record {name}.{domain}: {str(e)}")
            raise
    
    def create_subdomain(self, domain: str, subdomain: str, target: str, 
                        record_type: str = 'A', ttl: int = 1800) -> bool:
        """
        Create a subdomain record
        
        Args:
            domain: Parent domain
            subdomain: Subdomain name
            target: Target IP address or hostname
            record_type: Record type (A, CNAME)
            ttl: Time to live
            
        Returns:
            True if successful
        """
        return self.add_record(domain, subdomain, record_type, target, ttl, preserve_existing=True)
    
    def _split_domain(self, domain: str) -> Tuple[str, str]:
        """
        Split domain into Second Level Domain (SLD) and Top Level Domain (TLD)
        
        Args:
            domain: Full domain name
            
        Returns:
            Tuple of (SLD, TLD)
        """
        parts = domain.split('.')
        if len(parts) < 2:
            raise ValueError(f"Invalid domain format: {domain}")
        
        # Handle common multi-part TLDs
        if len(parts) >= 3:
            # Check for known multi-part TLDs
            possible_tld = '.'.join(parts[-2:])
            multi_part_tlds = [
                'co.uk', 'co.za', 'com.au', 'com.br', 'com.mx', 'org.uk', 
                'net.uk', 'gov.uk', 'edu.au', 'asn.au', 'id.au'
            ]
            
            if possible_tld.lower() in multi_part_tlds:
                return '.'.join(parts[:-2]), possible_tld
        
        # Default case: assume last part is TLD
        if len(parts) == 2:
            return parts[0], parts[1]
        else:
            return '.'.join(parts[:-1]), parts[-1]


class GoogleSiteVerification:
    """
    Google Site Verification API client
    """
    
    def __init__(self, service_account_path: str = None, service_account_info: Dict = None):
        """
        Initialize Google Site Verification client
        
        Args:
            service_account_path: Path to service account JSON file
            service_account_info: Service account info as dictionary
        """
        self.service = None
        self._initialize_service(service_account_path, service_account_info)
    
    def _initialize_service(self, service_account_path: str = None, service_account_info: Dict = None):
        """Initialize Google Site Verification service with credentials"""
        try:
            scopes = ['https://www.googleapis.com/auth/siteverification']
            
            if service_account_info:
                credentials = service_account.Credentials.from_service_account_info(
                    service_account_info, scopes=scopes
                )
            elif service_account_path and os.path.exists(service_account_path):
                credentials = service_account.Credentials.from_service_account_file(
                    service_account_path, scopes=scopes
                )
            else:
                raise ValueError("No valid Google service account credentials provided")
            
            self.service = build('siteverification', 'v1', credentials=credentials)
            logger.info("Initialized Google Site Verification service")
            
        except Exception as e:
            logger.error(f"Failed to initialize Google Site Verification: {str(e)}")
            raise
    
    def get_verification_token(self, domain: str, method: str = 'DNS_TXT') -> str:
        """
        Get verification token for domain
        
        Args:
            domain: Domain to verify
            method: Verification method (DNS_TXT, DNS_CNAME, FILE, META)
            
        Returns:
            Verification token string
        """
        try:
            request_body = {
                'site': {
                    'type': 'SITE',
                    'identifier': f'http://{domain}'
                },
                'verificationMethod': method
            }
            
            result = self.service.webResource().getToken(body=request_body).execute()
            token = result.get('token', '')
            
            logger.info(f"Generated verification token for {domain}")
            return token
            
        except Exception as e:
            logger.error(f"Failed to get verification token for {domain}: {str(e)}")
            raise
    
    def verify_domain(self, domain: str, method: str = 'DNS_TXT') -> bool:
        """
        Verify domain ownership
        
        Args:
            domain: Domain to verify
            method: Verification method
            
        Returns:
            True if verification successful
        """
        try:
            request_body = {
                'site': {
                    'type': 'SITE',
                    'identifier': f'http://{domain}'
                },
                'verificationMethod': method
            }
            
            result = self.service.webResource().insert(body=request_body).execute()
            
            if result.get('id'):
                logger.info(f"Successfully verified domain: {domain}")
                return True
            else:
                logger.warning(f"Domain verification returned no ID: {domain}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to verify domain {domain}: {str(e)}")
            raise
    
    def list_verified_sites(self) -> List[Dict]:
        """
        List all verified sites in the account
        
        Returns:
            List of verified site information
        """
        try:
            result = self.service.webResource().list().execute()
            sites = result.get('items', [])
            
            logger.info(f"Retrieved {len(sites)} verified sites")
            return sites
            
        except Exception as e:
            logger.error(f"Failed to list verified sites: {str(e)}")
            raise


class DNSManager:
    """
    Unified DNS management class combining Namecheap and Google Site Verification
    """
    
    def __init__(self, namecheap_config: Dict, google_config: Dict = None):
        """
        Initialize DNS Manager
        
        Args:
            namecheap_config: Namecheap API configuration
            google_config: Google API configuration (optional)
        """
        # Initialize Namecheap client
        self.namecheap = NamecheapAPI(**namecheap_config)
        
        # Initialize Google client if config provided
        self.google_verification = None
        if google_config:
            try:
                self.google_verification = GoogleSiteVerification(**google_config)
            except Exception as e:
                logger.warning(f"Failed to initialize Google verification: {str(e)}")
        
        logger.info("DNS Manager initialized successfully")
    
    def test_namecheap_connection(self) -> Dict:
        """Test Namecheap API connection"""
        return self.namecheap.test_connection()
    
    def get_domain_list(self) -> List[str]:
        """Get list of domains from Namecheap account"""
        return self.namecheap.get_domains_list()
    
    def get_dns_records(self, domain: str) -> List[Dict]:
        """Get DNS records for a domain"""
        return self.namecheap.get_host_records(domain)
    
    def create_subdomain_record(self, domain: str, subdomain: str, target: str, 
                              record_type: str = 'A', ttl: int = 1800) -> Dict:
        """
        Create subdomain with comprehensive error handling
        
        Args:
            domain: Parent domain
            subdomain: Subdomain name
            target: Target IP or hostname
            record_type: DNS record type
            ttl: Time to live
            
        Returns:
            Result dictionary with success status and details
        """
        try:
            success = self.namecheap.create_subdomain(domain, subdomain, target, record_type, ttl)
            
            return {
                'success': success,
                'domain': domain,
                'subdomain': subdomain,
                'target': target,
                'record_type': record_type,
                'ttl': ttl,
                'message': f'Successfully created {subdomain}.{domain} → {target}'
            }
            
        except NamecheapError as e:
            return {
                'success': False,
                'error': str(e),
                'error_code': e.error_code,
                'domain': domain,
                'subdomain': subdomain
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}',
                'domain': domain,
                'subdomain': subdomain
            }
    
    def verify_domain_with_google(self, domain: str) -> Dict:
        """
        Complete Google Site Verification workflow
        
        Args:
            domain: Domain to verify
            
        Returns:
            Result dictionary with verification status and details
        """
        if not self.google_verification:
            return {
                'success': False,
                'error': 'Google Site Verification not configured',
                'domain': domain
            }
        
        try:
            # Step 1: Get verification token
            token = self.google_verification.get_verification_token(domain)
            if not token:
                return {
                    'success': False,
                    'error': 'Failed to generate verification token',
                    'domain': domain
                }
            
            # Step 2: Add TXT record to DNS
            txt_success = self.namecheap.add_record(
                domain, '@', 'TXT', token, ttl=300, preserve_existing=True
            )
            
            if not txt_success:
                return {
                    'success': False,
                    'error': 'Failed to add verification TXT record',
                    'domain': domain,
                    'token': token
                }
            
            # Step 3: Wait for DNS propagation
            logger.info(f"Waiting for DNS propagation for {domain}")
            time.sleep(15)  # Allow time for DNS propagation
            
            # Step 4: Verify domain with Google
            verified = self.google_verification.verify_domain(domain)
            
            if verified:
                return {
                    'success': True,
                    'domain': domain,
                    'token': token,
                    'message': f'Successfully verified {domain} with Google'
                }
            else:
                return {
                    'success': False,
                    'error': 'Google verification failed - check DNS propagation',
                    'domain': domain,
                    'token': token
                }
                
        except Exception as e:
            logger.error(f"Domain verification failed for {domain}: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'domain': domain
            }
    
    def add_dns_record(self, domain: str, name: str, record_type: str, value: str, 
                      ttl: int = 1800, mx_pref: int = None) -> Dict:
        """
        Add DNS record with error handling
        
        Returns:
            Result dictionary
        """
        try:
            success = self.namecheap.add_record(
                domain, name, record_type, value, ttl, mx_pref, preserve_existing=True
            )
            
            return {
                'success': success,
                'domain': domain,
                'record': {
                    'name': name,
                    'type': record_type,
                    'value': value,
                    'ttl': ttl,
                    'mx_pref': mx_pref
                },
                'message': f'Successfully added {record_type} record for {name}.{domain}'
            }
            
        except NamecheapError as e:
            return {
                'success': False,
                'error': str(e),
                'error_code': e.error_code,
                'domain': domain
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}',
                'domain': domain
            }
    
    def delete_dns_record(self, domain: str, name: str, record_type: str = None) -> Dict:
        """
        Delete DNS record with error handling
        
        Returns:
            Result dictionary
        """
        try:
            success = self.namecheap.delete_record(domain, name, record_type)
            
            return {
                'success': success,
                'domain': domain,
                'deleted_record': {
                    'name': name,
                    'type': record_type
                },
                'message': f'Successfully deleted {record_type or "all"} record(s) for {name}.{domain}'
            }
            
        except NamecheapError as e:
            return {
                'success': False,
                'error': str(e),
                'error_code': e.error_code,
                'domain': domain
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}',
                'domain': domain
            }