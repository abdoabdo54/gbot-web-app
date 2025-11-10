"""
DNS API routes
"""
import logging
import os
from typing import Dict
from flask import Blueprint, request, jsonify, session
from functools import wraps

from database import db, NamecheapConfig, DNSRecord, GoogleVerification
from dns_manager import DNSManager
import config

logger = logging.getLogger('dns_module')

dns_bp = Blueprint('dns_api', __name__, url_prefix='/api/dns')


def login_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if not (session.get('user') or session.get('emergency_access')):
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return inner


def _nc_conf() -> Dict:
    c = NamecheapConfig.query.filter_by(is_active=True).first()
    if c:
        return {
            'api_user': c.api_user,
            'api_key': c.api_key,  # !!! PLAIN STORAGE — REPLACE BEFORE PROD
            'username': c.username,
            'client_ip': c.client_ip,
            'sandbox': c.is_sandbox,
        }
    # fallback to env
    if all([config.NAMECHEAP_API_USER, config.NAMECHEAP_API_KEY, config.NAMECHEAP_USERNAME, config.NAMECHEAP_CLIENT_IP]):
        return {
            'api_user': config.NAMECHEAP_API_USER,
            'api_key': config.NAMECHEAP_API_KEY,
            'username': config.NAMECHEAP_USERNAME,
            'client_ip': config.NAMECHEAP_CLIENT_IP,
            'sandbox': config.NAMECHEAP_SANDBOX,
        }
    return {}


def _manager() -> DNSManager:
    nc = _nc_conf()
    if not nc:
        raise RuntimeError('Namecheap not configured')
    google_path = getattr(config, 'GOOGLE_SERVICE_ACCOUNT_PATH', None)
    return DNSManager(nc, google_path)


# Config endpoints
@dns_bp.route('/namecheap/config', methods=['POST'])
@login_required
def save_nc_config():
    data = request.get_json() or {}
    req = ['api_user', 'api_key', 'username', 'client_ip']
    miss = [k for k in req if not data.get(k)]
    if miss:
        return jsonify({'success': False, 'error': f'Missing: {", ".join(miss)}'}), 400
    NamecheapConfig.query.update({'is_active': False})
    rec = NamecheapConfig(
        api_user=data['api_user'].strip(),
        api_key=data['api_key'].strip(),  # !!! PLAIN STORAGE — REPLACE BEFORE PROD
        username=data['username'].strip(),
        client_ip=data['client_ip'].strip(),
        is_sandbox=bool(data.get('sandbox', False)),
        is_active=True
    )
    db.session.add(rec)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Saved', 'warning': 'Credentials stored in plain text — replace before prod'})

@dns_bp.route('/namecheap/config', methods=['GET'])
@login_required
def get_nc_config():
    c = NamecheapConfig.query.filter_by(is_active=True).first()
    if not c:
        return jsonify({'success': False, 'configured': False})
    return jsonify({'success': True, 'configured': True, 'config': {
        'api_user': c.api_user,
        'username': c.username,
        'client_ip': c.client_ip,
        'sandbox': c.is_sandbox,
        'created_at': c.created_at.isoformat() if c.created_at else None
    }})


# Domains
@dns_bp.route('/namecheap/domains', methods=['GET'])
@login_required
def list_domains():
    try:
        mgr = _manager()
        domains = mgr.list_domains()
        return jsonify({'success': True, 'domains': domains, 'count': len(domains)})
    except Exception as e:
        logger.error(f"list_domains: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# Hosts
@dns_bp.route('/namecheap/hosts', methods=['GET'])
@login_required
def list_hosts():
    domain = request.args.get('domain', '').strip().lower()
    if not domain:
        return jsonify({'success': False, 'error': 'domain is required'}), 400
    try:
        mgr = _manager()
        hosts = mgr.list_hosts(domain)
        return jsonify({'success': True, 'domain': domain, 'hosts': hosts})
    except Exception as e:
        logger.error(f"list_hosts: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# Upsert record
@dns_bp.route('/namecheap/record', methods=['POST'])
@login_required
def upsert_record():
    data = request.get_json() or {}
    req = ['domain', 'host', 'type', 'value']
    miss = [k for k in req if not data.get(k)]
    if miss:
        return jsonify({'success': False, 'error': f'Missing: {", ".join(miss)}'}), 400
    ttl = int(data.get('ttl', config.DNS_DEFAULT_TTL))
    try:
        mgr = _manager()
        mgr.upsert_record(data['domain'].strip().lower(), data['host'].strip(), data['type'].strip().upper(), data['value'].strip(), ttl, data.get('mx_pref'))
        # log history
        db.session.add(DNSRecord(domain=data['domain'].strip().lower(), record_name=data['host'].strip(), record_type=data['type'].strip().upper(), record_value=data['value'].strip(), ttl=ttl, mx_preference=data.get('mx_pref'), created_by=session.get('user'), is_active=True))
        db.session.commit()
        return jsonify({'success': True, 'message': 'Record saved'})
    except Exception as e:
        logger.error(f"upsert_record: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# Verification
@dns_bp.route('/namecheap/verify-domain', methods=['POST'])
@login_required
def verify_domain():
    data = request.get_json() or {}
    domain = data.get('domain', '').strip().lower()
    host = data.get('host', '@')
    auto = bool(data.get('auto_verify', True))
    if not domain:
        return jsonify({'success': False, 'error': 'domain is required'}), 400
    try:
        mgr = _manager()
        tok = mgr.generate_txt_and_apply(domain, host)
        result = {'token': tok['token']}
        if auto:
            ver = mgr.verify_domain(domain)
            result['verify'] = ver
            # persist verification
            if ver.get('success'):
                db.session.add(GoogleVerification(domain=domain, verification_token=tok['token'], verification_method='DNS_TXT', is_verified=True, verified_at=db.func.current_timestamp()))
                db.session.commit()
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        logger.error(f"verify_domain: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# Logs
@dns_bp.route('/logs', methods=['GET'])
@login_required
def tail_logs():
    try:
        lines = []
        path = os.path.join('logs', 'dns_module.log') if 'os' in globals() else 'logs/dns_module.log'
        import os as _os
        path = _os.path.join(_os.getcwd(), 'logs', 'dns_module.log')
        if _os.path.exists(path):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()[-200:]
        return jsonify({'success': True, 'lines': [l.rstrip('\n') for l in lines]})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
