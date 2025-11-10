"""
Production-ready DNS Manager for GBot Web App
- Namecheap API client (domains.getList, dns.getHosts, dns.setHosts)
- Safe merge logic for setHosts
- Google Site Verification helpers
"""
import logging
import os
import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple, Optional
import requests

from googleapiclient.discovery import build
from google.oauth2 import service_account

logger = logging.getLogger('dns_module')
if not logger.handlers:
    logger.setLevel(logging.INFO)
    try:
        os.makedirs('logs', exist_ok=True)
        fh = logging.FileHandler('logs/dns_module.log')
        fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        logger.addHandler(fh)
    except Exception:
        logging.basicConfig(level=logging.INFO)


class NamecheapAPIError(Exception):
    pass


class NamecheapClient:
    """Thin client around Namecheap XML API."""
    def __init__(self, api_user: str, api_key: str, username: str, client_ip: str, sandbox: bool = False):
        self.api_user = api_user
        self.api_key = api_key
        self.username = username
        self.client_ip = client_ip
        self.base_url = 'https://api.sandbox.namecheap.com/xml.response' if sandbox else 'https://api.namecheap.com/xml.response'

    def _request(self, command: str, params: Dict) -> ET.Element:
        all_params = {
            'ApiUser': self.api_user,
            'ApiKey': self.api_key,
            'UserName': self.username,
            'ClientIp': self.client_ip,
            'Command': command,
            **params
        }
        logger.info(f"NC call {command} for {params.get('SLD','')} {params.get('TLD','')} {params.get('DomainList','')}")
        try:
            resp = requests.get(self.base_url, params=all_params, timeout=30)
            resp.raise_for_status()
            root = ET.fromstring(resp.content)
        except Exception as e:
            logger.error(f"HTTP/XML error for {command}: {e}")
            raise NamecheapAPIError(f"Request failed: {e}")
        status = root.get('Status')
        if status != 'OK':
            errors = [err.text for err in root.findall('.//Error')]
            msg = '; '.join(errors) if errors else f"Status {status}"
            logger.error(f"Namecheap error {command}: {msg}")
            raise NamecheapAPIError(msg)
        return root

    @staticmethod
    def _split_domain(domain: str) -> Tuple[str, str]:
        parts = domain.strip().split('.')
        if len(parts) < 2:
            raise ValueError('Invalid domain')
        # handle common multi-part TLDs simply by taking last part as TLD
        return '.'.join(parts[:-1]), parts[-1]

    def get_domains(self) -> List[Dict]:
        root = self._request('namecheap.domains.getList', {'Page': 1, 'PageSize': 100, 'ListType': 'ALL', 'SortBy': 'NAME'})
        out = []
        for d in root.findall('.//Domain'):
            out.append({
                'Name': d.get('Name'),
                'IsOurDNS': d.get('IsOurDNS'),
                'Expires': d.get('Expires')
            })
        return out

    def get_hosts(self, domain: str) -> List[Dict]:
        sld, tld = self._split_domain(domain)
        root = self._request('namecheap.domains.dns.getHosts', {'SLD': sld, 'TLD': tld})
        hosts = []
        for h in root.findall('.//host'):
            hosts.append({
                'Name': h.get('Name', '@'),
                'Type': h.get('Type'),
                'Address': h.get('Address'),
                'TTL': h.get('TTL') or '1800',
                'MXPref': h.get('MXPref')
            })
        return hosts

    def set_hosts(self, domain: str, hosts: List[Dict]) -> bool:
        sld, tld = self._split_domain(domain)
        params = {'SLD': sld, 'TLD': tld}
        for i, r in enumerate(hosts, 1):
            params[f'HostName{i}'] = r.get('Name', '@')
            params[f'RecordType{i}'] = r.get('Type', 'A')
            params[f'Address{i}'] = r.get('Address', '')
            if r.get('TTL'): params[f'TTL{i}'] = str(r.get('TTL'))
            if r.get('Type') == 'MX' and r.get('MXPref'):
                params[f'MXPref{i}'] = str(r.get('MXPref'))
        root = self._request('namecheap.domains.dns.setHosts', params)
        res = root.find('.//DomainDNSSetHostsResult')
        ok = res is not None and res.get('IsSuccess') == 'true'
        if not ok:
            raise NamecheapAPIError('setHosts failed')
        return True

    def add_or_update_record(self, domain: str, host: str, rtype: str, value: str, ttl: int = 1800, mx_pref: Optional[int] = None) -> bool:
        current = self.get_hosts(domain)
        updated = False
        for rec in current:
            if rec['Name'] == host and rec['Type'].upper() == rtype.upper():
                rec['Address'] = value
                rec['TTL'] = str(ttl)
                if rtype.upper() == 'MX' and mx_pref is not None:
                    rec['MXPref'] = str(mx_pref)
                updated = True
                break
        if not updated:
            newr = {'Name': host, 'Type': rtype.upper(), 'Address': value, 'TTL': str(ttl)}
            if rtype.upper() == 'MX' and mx_pref is not None:
                newr['MXPref'] = str(mx_pref)
            current.append(newr)
        return self.set_hosts(domain, current)

    def add_or_update_txt(self, domain: str, host: str, value: str, ttl: int = 300) -> bool:
        return self.add_or_update_record(domain, host, 'TXT', value, ttl)


class GoogleVerificationClient:
    def __init__(self, service_account_path: Optional[str]):
        self.service = None
        if service_account_path and os.path.exists(service_account_path):
            creds = service_account.Credentials.from_service_account_file(
                service_account_path,
                scopes=['https://www.googleapis.com/auth/siteverification']
            )
            self.service = build('siteverification', 'v1', credentials=creds)

    def get_token(self, domain: str) -> Dict:
        if not self.service:
            raise RuntimeError('Google Site Verification not configured')
        body = {
            'site': {'type': 'INET_DOMAIN', 'identifier': domain},
            'verificationMethod': 'DNS_TXT'
        }
        resp = self.service.webResource().getToken(body=body).execute()
        return {'method': 'DNS_TXT', 'token': resp.get('token')}

    def verify(self, domain: str, owners: Optional[List[str]] = None) -> Dict:
        if not self.service:
            raise RuntimeError('Google Site Verification not configured')
        body = {'site': {'type': 'INET_DOMAIN', 'identifier': domain}}
        req = self.service.webResource().insert(verificationMethod='DNS_TXT', body=body)
        res = req.execute()
        return {'id': res.get('id'), 'success': bool(res.get('id'))}


class DNSManager:
    def __init__(self, nc_conf: Dict, google_sa_path: Optional[str] = None):
        self.nc = NamecheapClient(
            api_user=nc_conf['api_user'],
            api_key=nc_conf['api_key'],
            username=nc_conf['username'],
            client_ip=nc_conf['client_ip'],
            sandbox=nc_conf.get('sandbox', False)
        )
        self.gclient = GoogleVerificationClient(google_sa_path)

    # Namecheap wrappers
    def list_domains(self) -> List[Dict]:
        return self.nc.get_domains()

    def list_hosts(self, domain: str) -> List[Dict]:
        return self.nc.get_hosts(domain)

    def upsert_record(self, domain: str, host: str, rtype: str, value: str, ttl: int, mx_pref: Optional[int] = None) -> bool:
        return self.nc.add_or_update_record(domain, host, rtype, value, ttl, mx_pref)

    # Google verification flow
    def generate_txt_and_apply(self, domain: str, host: str = '@') -> Dict:
        tok = self.gclient.get_token(domain)
        self.nc.add_or_update_txt(domain, host, tok['token'], ttl=300)
        return tok

    def verify_domain(self, domain: str) -> Dict:
        return self.gclient.verify(domain)
