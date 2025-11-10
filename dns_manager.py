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
    sh = logging.StreamHandler()
    sh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(sh)
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
        logger.info(f"NC call {command} for SLD={params.get('SLD','')} TLD={params.get('TLD','')} DomainList={params.get('DomainList','')}")
        try:
            resp = requests.get(self.base_url, params=all_params, timeout=30)
            logger.info(f"NC endpoint: {self.base_url} | user={self.username} ip={self.client_ip} cmd={command}")
            logger.info(f"NC params keys: {list(all_params.keys())}")
            resp.raise_for_status()
            root = ET.fromstring(resp.content)
        except Exception as e:
            preview = ''
            try:
                preview = resp.text[:500] if 'resp' in locals() else ''
            except Exception:
                pass
            logger.error(f"HTTP/XML error for {command}: {e} | preview={preview}")
            raise NamecheapAPIError(f"Request failed: {e}")
        status = root.get('Status')
        if status != 'OK':
            errs = []
            for err in root.findall('.//Error'):
                num = err.get('Number', 'Unknown')
                txt = (err.text or '').strip()
                errs.append(f"#{num} {txt}")
            msg = '; '.join(errs) if errs else f"Status {status}"
            logger.error(f"Namecheap error {command}: {msg}")
            logger.error(f"Raw response preview: {resp.text[:800]}")
            raise NamecheapAPIError(msg)
        return root

    @staticmethod
    def _split_domain(domain: str) -> Tuple[str, str]:
        parts = domain.strip().split('.')
        if len(parts) < 2:
            raise ValueError('Invalid domain')
        # handle common multi-part TLDs simply by taking last part as TLD
        return '.'.join(parts[:-1]), parts[-1]

    def detect_public_ip(self) -> Optional[str]:
        try:
            for url in ['https://api.ipify.org', 'https://ifconfig.me/ip', 'https://ipinfo.io/ip']:
                try:
                    r = requests.get(url, timeout=5)
                    if r.ok:
                        return r.text.strip()
                except Exception:
                    continue
        except Exception:
            pass
        return None

    def get_domains(self) -> List[Dict]:
        info = self.get_domains_info()
        return info['domains']

    def get_domains_info(self) -> Dict:
        out: List[Dict] = []
        total = None
        page_size = 100
        page = 1
        while True:
            root = self._request('namecheap.domains.getList', {'Page': page, 'PageSize': page_size, 'ListType': 'ALL', 'SortBy': 'NAME'})
            batch = []
            for d in root.findall('.//Domain'):
                batch.append({
                    'Name': d.get('Name'),
                    'IsOurDNS': d.get('IsOurDNS'),
                    'Expires': d.get('Expires')
                })
            out.extend(batch)
            # paging info
            if total is None:
                try:
                    pg = root.find('.//Paging')
                    if pg is not None:
                        total = int((pg.findtext('TotalItems') or '0').strip() or '0')
                        page_size = int((pg.findtext('PageSize') or '100').strip() or '100')
                except Exception:
                    total = len(out)
            logger.info(f"getList page {page} fetched {len(batch)} items; cumulative {len(out)} / total {total}")
            # break when collected all or no more
            if total is None or len(out) >= total or len(batch) == 0:
                break
            page += 1
        return {'domains': out, 'total': total or len(out), 'page': page, 'page_size': page_size}

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

    def debug_get_domains_attempts(self, try_username_as_apiuser: bool = True, try_detect_ip: bool = True) -> List[Dict]:
        attempts = []
        # Attempt 1: current config
        try:
            domains = self.get_domains()
            attempts.append({'attempt': 'current', 'success': True, 'count': len(domains)})
            return attempts
        except Exception as e:
            attempts.append({'attempt': 'current', 'success': False, 'error': str(e)})
        # Attempt 2: username = api_user
        if try_username_as_apiuser and self.username != self.api_user:
            try:
                saved_username = self.username
                self.username = self.api_user
                domains = self.get_domains()
                attempts.append({'attempt': 'username=api_user', 'success': True, 'count': len(domains)})
                # restore
                self.username = saved_username
                return attempts
            except Exception as e:
                attempts.append({'attempt': 'username=api_user', 'success': False, 'error': str(e)})
                self.username = saved_username
        # Attempt 3: override client IP with detected public IP
        if try_detect_ip:
            ip = self.detect_public_ip()
            if ip and ip != self.client_ip:
                try:
                    saved_ip = self.client_ip
                    self.client_ip = ip
                    domains = self.get_domains()
                    attempts.append({'attempt': f'client_ip={ip}', 'success': True, 'count': len(domains)})
                    self.client_ip = saved_ip
                    return attempts
                except Exception as e:
                    attempts.append({'attempt': f'client_ip={ip}', 'success': False, 'error': str(e)})
                    self.client_ip = saved_ip
        return attempts


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
