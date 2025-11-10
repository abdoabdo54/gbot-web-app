"""
DNS API Blueprint for GBot Web App
RESTful endpoints for DNS management and Google Site Verification
"""

import os
import json
import logging
from typing import Dict, List
from flask import Blueprint, request, jsonify, session
from functools import wraps

from database import db, NamecheapConfig, DNSRecord, GoogleVerification
from dns_manager import DNSManager, NamecheapError
import config

# Configure logging
logger = logging.getLogger(__name__)

# Create Blueprint
dns_bp = Blueprint('dns_api', __name__, url_prefix='/api/dns')


def login_required(f):
    """Decorator to require login for DNS API endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not (session.get('user') or session.get('emergency_access')):
            return jsonify({
                'success': False,
                'error': 'Authentication required'
            }), 401
        return f(*args, **kwargs)
    return decorated_function


def get_dns_manager() -> DNSManager:
    """
    Initialize DNS Manager with current configuration
    
    Returns:
        Configured DNSManager instance or None if not configured
    """
    try:
        # Get Namecheap configuration from database
        namecheap_config = NamecheapConfig.query.filter_by(is_active=True).first()
        
        if not namecheap_config:
            # Fallback to environment variables
            if not all([
                config.NAMECHEAP_API_USER, 
                config.NAMECHEAP_API_KEY,
                config.NAMECHEAP_USERNAME, 
                config.NAMECHEAP_CLIENT_IP
            ]):
                return None
                
            nc_config = {
                'api_user': config.NAMECHEAP_API_USER,
                'api_key': config.NAMECHEAP_API_KEY,
                'username': config.NAMECHEAP_USERNAME,
                'client_ip': config.NAMECHEAP_CLIENT_IP,
                'sandbox': config.NAMECHEAP_SANDBOX
            }
        else:
            nc_config = {
                'api_user': namecheap_config.api_user,
                'api_key': namecheap_config.api_key,
                'username': namecheap_config.username,
                'client_ip': namecheap_config.client_ip,
                'sandbox': namecheap_config.is_sandbox
            }
        
        # Google configuration (optional)
        google_config = None
        if hasattr(config, 'GOOGLE_SERVICE_ACCOUNT_PATH') and config.GOOGLE_SERVICE_ACCOUNT_PATH:
            google_config = {'service_account_path': config.GOOGLE_SERVICE_ACCOUNT_PATH}
        elif hasattr(config, 'GOOGLE_SERVICE_ACCOUNT_INFO') and config.GOOGLE_SERVICE_ACCOUNT_INFO:
            google_config = {'service_account_info': config.GOOGLE_SERVICE_ACCOUNT_INFO}
        
        return DNSManager(nc_config, google_config)
        
    except Exception as e:
        logger.error(f"Failed to initialize DNS manager: {str(e)}")
        return None


# Configuration endpoints
@dns_bp.route('/config', methods=['GET'])
@login_required
def get_dns_config():
    """Get current DNS configuration status"""
    try:
        config_obj = NamecheapConfig.query.filter_by(is_active=True).first()
        
        if not config_obj:
            return jsonify({
                'success': False,
                'configured': False,
                'message': 'DNS not configured'
            })
        
        return jsonify({
            'success': True,
            'configured': True,
            'config': {
                'api_user': config_obj.api_user,
                'username': config_obj.username,
                'client_ip': config_obj.client_ip,
                'sandbox': config_obj.is_sandbox,
                'created_at': config_obj.created_at.isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Failed to get DNS config: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Configuration error: {str(e)}'
        }), 500


@dns_bp.route('/config', methods=['POST'])
@login_required
def set_dns_config():
    """Set DNS configuration"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['api_user', 'api_key', 'username', 'client_ip']
        missing_fields = [f for f in required_fields if not data.get(f)]
        if missing_fields:
            return jsonify({
                'success': False,
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        # Deactivate existing configurations
        NamecheapConfig.query.update({'is_active': False})
        
        # Create new configuration
        config_obj = NamecheapConfig(
            api_user=data['api_user'].strip(),
            api_key=data['api_key'].strip(),  # !!! PLAIN STORAGE — REPLACE BEFORE PROD
            username=data['username'].strip(),
            client_ip=data['client_ip'].strip(),
            is_sandbox=data.get('sandbox', False),
            is_active=True
        )
        
        db.session.add(config_obj)
        db.session.commit()
        
        logger.info(f"DNS configuration saved for user: {data['username']}")
        
        return jsonify({
            'success': True,
            'message': 'DNS configuration saved successfully',
            'warning': '⚠️ API credentials stored in plain text - encrypt before production!'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to save DNS config: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to save configuration: {str(e)}'
        }), 500


# Connection and domain endpoints
@dns_bp.route('/test-connection', methods=['POST'])
@login_required
def test_connection():
    """Test DNS service connection"""
    try:
        dns_manager = get_dns_manager()
        
        if not dns_manager:
            return jsonify({
                'success': False,
                'error': 'DNS not configured'
            }), 400
        
        # Test Namecheap connection
        namecheap_result = dns_manager.test_namecheap_connection()
        
        return jsonify({
            'success': namecheap_result.get('success', False),
            'namecheap': namecheap_result,
            'message': 'Connection test completed'
        })
        
    except Exception as e:
        logger.error(f"Connection test failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Connection test failed: {str(e)}'
        }), 500


@dns_bp.route('/domains', methods=['GET'])
@login_required
def get_domains():
    """Get list of domains from Namecheap account"""
    try:
        dns_manager = get_dns_manager()
        
        if not dns_manager:
            return jsonify({
                'success': False,
                'error': 'DNS not configured'
            }), 400
        
        domains = dns_manager.get_domain_list()
        
        return jsonify({
            'success': True,
            'domains': domains,
            'count': len(domains)
        })
        
    except Exception as e:
        logger.error(f"Failed to get domains: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to retrieve domains: {str(e)}'
        }), 500


@dns_bp.route('/records/<domain>', methods=['GET'])
@login_required
def get_dns_records(domain):
    """Get DNS records for a specific domain"""
    try:
        dns_manager = get_dns_manager()
        
        if not dns_manager:
            return jsonify({
                'success': False,
                'error': 'DNS not configured'
            }), 400
        
        records = dns_manager.get_dns_records(domain)
        
        return jsonify({
            'success': True,
            'domain': domain,
            'records': records,
            'count': len(records)
        })
        
    except Exception as e:
        logger.error(f"Failed to get DNS records for {domain}: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to retrieve DNS records: {str(e)}'
        }), 500


# DNS record management endpoints
@dns_bp.route('/namecheap/subdomain', methods=['POST'])
@login_required
def create_subdomain():
    """Create or update a subdomain record"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['domain', 'subdomain', 'target']
        missing_fields = [f for f in required_fields if not data.get(f)]
        if missing_fields:
            return jsonify({
                'success': False,
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        domain = data['domain'].strip().lower()
        subdomain = data['subdomain'].strip().lower()
        target = data['target'].strip()
        record_type = data.get('record_type', 'A').upper()
        ttl = data.get('ttl', config.DNS_DEFAULT_TTL)
        
        # Validate record type
        valid_types = ['A', 'CNAME', 'TXT', 'MX']
        if record_type not in valid_types:
            return jsonify({
                'success': False,
                'error': f'Invalid record type. Must be one of: {", ".join(valid_types)}'
            }), 400
        
        dns_manager = get_dns_manager()
        if not dns_manager:
            return jsonify({
                'success': False,
                'error': 'DNS not configured'
            }), 400
        
        # Create subdomain
        result = dns_manager.create_subdomain_record(domain, subdomain, target, record_type, ttl)
        
        # Log to database if successful
        if result.get('success'):
            try:
                dns_record = DNSRecord(
                    domain=domain,
                    record_name=subdomain,
                    record_type=record_type,
                    record_value=target,
                    ttl=ttl,
                    created_by=session.get('user'),
                    is_active=True
                )
                db.session.add(dns_record)
                db.session.commit()
            except Exception as e:
                logger.warning(f"Failed to log DNS record to database: {str(e)}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Failed to create subdomain: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to create subdomain: {str(e)}'
        }), 500


@dns_bp.route('/records', methods=['POST'])
@login_required
def add_dns_record():
    """Add or update a DNS record"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['domain', 'name', 'type', 'value']
        missing_fields = [f for f in required_fields if not data.get(f)]
        if missing_fields:
            return jsonify({
                'success': False,
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        domain = data['domain'].strip().lower()
        name = data['name'].strip()
        record_type = data['type'].strip().upper()
        value = data['value'].strip()
        ttl = data.get('ttl', config.DNS_DEFAULT_TTL)
        mx_pref = data.get('mx_pref')
        
        # Validate record type
        valid_types = ['A', 'CNAME', 'TXT', 'MX']
        if record_type not in valid_types:
            return jsonify({
                'success': False,
                'error': f'Invalid record type. Must be one of: {", ".join(valid_types)}'
            }), 400
        
        dns_manager = get_dns_manager()
        if not dns_manager:
            return jsonify({
                'success': False,
                'error': 'DNS not configured'
            }), 400
        
        # Add DNS record
        result = dns_manager.add_dns_record(domain, name, record_type, value, ttl, mx_pref)
        
        # Log to database if successful
        if result.get('success'):
            try:
                dns_record = DNSRecord(
                    domain=domain,
                    record_name=name,
                    record_type=record_type,
                    record_value=value,
                    ttl=ttl,
                    mx_preference=mx_pref,
                    created_by=session.get('user'),
                    is_active=True
                )
                db.session.add(dns_record)
                db.session.commit()
            except Exception as e:
                logger.warning(f"Failed to log DNS record to database: {str(e)}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Failed to add DNS record: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to add DNS record: {str(e)}'
        }), 500


@dns_bp.route('/records', methods=['DELETE'])
@login_required
def delete_dns_record():
    """Delete a DNS record"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('domain') or not data.get('name'):
            return jsonify({
                'success': False,
                'error': 'Domain and record name are required'
            }), 400
        
        domain = data['domain'].strip().lower()
        name = data['name'].strip()
        record_type = data.get('type', '').strip().upper() or None
        
        dns_manager = get_dns_manager()
        if not dns_manager:
            return jsonify({
                'success': False,
                'error': 'DNS not configured'
            }), 400
        
        # Delete DNS record
        result = dns_manager.delete_dns_record(domain, name, record_type)
        
        # Update database records if successful
        if result.get('success'):
            try:
                query = DNSRecord.query.filter_by(domain=domain, record_name=name, is_active=True)
                if record_type:
                    query = query.filter_by(record_type=record_type)
                
                deleted_records = query.all()
                for record in deleted_records:
                    record.is_active = False
                
                db.session.commit()
            except Exception as e:
                logger.warning(f"Failed to update DNS record status: {str(e)}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Failed to delete DNS record: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to delete DNS record: {str(e)}'
        }), 500


# Google Site Verification endpoints
@dns_bp.route('/namecheap/verify-domain', methods=['POST'])
@login_required
def verify_domain():
    """Complete Google Site Verification workflow"""
    try:
        data = request.get_json()
        
        if not data.get('domain'):
            return jsonify({
                'success': False,
                'error': 'Domain is required'
            }), 400
        
        domain = data['domain'].strip().lower()
        
        dns_manager = get_dns_manager()
        if not dns_manager:
            return jsonify({
                'success': False,
                'error': 'DNS not configured'
            }), 400
        
        # Perform Google verification workflow
        result = dns_manager.verify_domain_with_google(domain)
        
        # Log verification attempt
        if result.get('success'):
            try:
                verification = GoogleVerification.query.filter_by(domain=domain).first()
                if not verification:
                    verification = GoogleVerification(domain=domain)
                
                verification.verification_token = result.get('token')
                verification.verification_method = 'DNS_TXT'
                verification.is_verified = True
                verification.verified_at = db.func.current_timestamp()
                
                db.session.add(verification)
                db.session.commit()
            except Exception as e:
                logger.warning(f"Failed to log verification to database: {str(e)}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Failed to verify domain: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to verify domain: {str(e)}'
        }), 500


@dns_bp.route('/google/verification-token', methods=['POST'])
@login_required
def get_verification_token():
    """Get Google verification token (without verification)"""
    try:
        data = request.get_json()
        
        if not data.get('domain'):
            return jsonify({
                'success': False,
                'error': 'Domain is required'
            }), 400
        
        domain = data['domain'].strip().lower()
        
        dns_manager = get_dns_manager()
        if not dns_manager or not dns_manager.google_verification:
            return jsonify({
                'success': False,
                'error': 'Google Site Verification not configured'
            }), 400
        
        # Get verification token only
        token = dns_manager.google_verification.get_verification_token(domain)
        
        return jsonify({
            'success': True,
            'domain': domain,
            'token': token,
            'message': 'Verification token generated successfully'
        })
        
    except Exception as e:
        logger.error(f"Failed to get verification token: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to get verification token: {str(e)}'
        }), 500


# History and monitoring endpoints
@dns_bp.route('/records/history', methods=['GET'])
@login_required
def get_dns_history():
    """Get DNS records history"""
    try:
        domain = request.args.get('domain', '')
        limit = int(request.args.get('limit', 100))
        
        query = DNSRecord.query.order_by(DNSRecord.created_at.desc())
        
        if domain:
            query = query.filter_by(domain=domain)
        
        records = query.limit(limit).all()
        
        history = []
        for record in records:
            history.append({
                'id': record.id,
                'domain': record.domain,
                'record_name': record.record_name,
                'record_type': record.record_type,
                'record_value': record.record_value,
                'ttl': record.ttl,
                'mx_preference': record.mx_preference,
                'is_active': record.is_active,
                'created_by': record.created_by,
                'created_at': record.created_at.isoformat() if record.created_at else None,
                'updated_at': record.updated_at.isoformat() if record.updated_at else None
            })
        
        return jsonify({
            'success': True,
            'records': history,
            'total': len(history),
            'domain_filter': domain
        })
        
    except Exception as e:
        logger.error(f"Failed to get DNS history: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to get DNS history: {str(e)}'
        }), 500


@dns_bp.route('/google/verified-sites', methods=['GET'])
@login_required
def get_verified_sites():
    """Get list of Google-verified sites"""
    try:
        dns_manager = get_dns_manager()
        if not dns_manager or not dns_manager.google_verification:
            return jsonify({
                'success': False,
                'error': 'Google Site Verification not configured'
            }), 400
        
        # Get verified sites from Google
        sites = dns_manager.google_verification.list_verified_sites()
        
        # Get verification history from database
        db_verifications = GoogleVerification.query.filter_by(is_verified=True).all()
        
        db_sites = []
        for verification in db_verifications:
            db_sites.append({
                'domain': verification.domain,
                'verified_at': verification.verified_at.isoformat() if verification.verified_at else None,
                'verification_method': verification.verification_method
            })
        
        return jsonify({
            'success': True,
            'google_sites': sites,
            'database_sites': db_sites
        })
        
    except Exception as e:
        logger.error(f"Failed to get verified sites: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to get verified sites: {str(e)}'
        }), 500


# Health check endpoint
@dns_bp.route('/health', methods=['GET'])
def health_check():
    """DNS module health check"""
    try:
        dns_manager = get_dns_manager()
        
        return jsonify({
            'success': True,
            'dns_configured': dns_manager is not None,
            'google_verification_configured': (
                dns_manager.google_verification is not None 
                if dns_manager else False
            ),
            'timestamp': db.func.current_timestamp().op('||')('')
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500