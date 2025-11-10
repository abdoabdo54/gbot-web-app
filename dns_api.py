"""
DNS API endpoints for GBot Web App
Provides RESTful API for Namecheap DNS management and Google Site Verification
"""

from flask import Blueprint, request, jsonify, session
from functools import wraps
import json
import logging
from datetime import datetime

from database import db, NamecheapConfig, DNSRecord, GoogleVerification
from dns_manager import DNSManager, NamecheapAPI, GoogleSiteVerification
import config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Blueprint
dns_bp = Blueprint('dns_api', __name__, url_prefix='/api/dns')


def login_required(f):
    """Decorator to require login for API endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({
                'success': False,
                'error': 'Authentication required'
            }), 401
        return f(*args, **kwargs)
    return decorated_function


def get_dns_manager():
    """
    Get configured DNS manager instance
    
    Returns:
        DNSManager instance or None if not configured
    """
    try:
        # Get Namecheap config from database or environment
        namecheap_config = NamecheapConfig.query.filter_by(is_active=True).first()
        
        if namecheap_config:
            nc_config = {
                'api_user': namecheap_config.api_user,
                'api_key': namecheap_config.api_key,
                'username': namecheap_config.username,
                'client_ip': namecheap_config.client_ip,
                'sandbox': namecheap_config.is_sandbox
            }
        else:
            # Fallback to environment variables
            if not all([config.NAMECHEAP_API_USER, config.NAMECHEAP_API_KEY, 
                       config.NAMECHEAP_USERNAME, config.NAMECHEAP_CLIENT_IP]):
                return None
                
            nc_config = {
                'api_user': config.NAMECHEAP_API_USER,
                'api_key': config.NAMECHEAP_API_KEY,
                'username': config.NAMECHEAP_USERNAME,
                'client_ip': config.NAMECHEAP_CLIENT_IP,
                'sandbox': config.NAMECHEAP_SANDBOX
            }
        
        # For Google verification, we'll use the existing Google API setup
        # This would typically use the same service account as the main app
        google_config = None  # Will be implemented based on existing Google auth
        
        return DNSManager(nc_config, google_config)
        
    except Exception as e:
        logger.error(f"Failed to initialize DNS manager: {str(e)}")
        return None


@dns_bp.route('/namecheap/config', methods=['GET'])
@login_required
def get_namecheap_config():
    """Get current Namecheap configuration"""
    try:
        config_obj = NamecheapConfig.query.filter_by(is_active=True).first()
        
        if not config_obj:
            return jsonify({
                'success': False,
                'configured': False,
                'message': 'Namecheap API not configured'
            })
        
        return jsonify({
            'success': True,
            'configured': True,
            'config': {
                'api_user': config_obj.api_user,
                'username': config_obj.username,
                'client_ip': config_obj.client_ip,
                'is_sandbox': config_obj.is_sandbox,
                'created_at': config_obj.created_at.isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Failed to get Namecheap config: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to get configuration: {str(e)}'
        }), 500


@dns_bp.route('/namecheap/config', methods=['POST'])
@login_required
def set_namecheap_config():
    """Set Namecheap API configuration"""
    try:
        data = request.get_json()
        
        required_fields = ['api_user', 'api_key', 'username', 'client_ip']
        if not all(field in data for field in required_fields):
            return jsonify({
                'success': False,
                'error': 'Missing required fields: ' + ', '.join(required_fields)
            }), 400
        
        # Deactivate existing configs
        NamecheapConfig.query.update({'is_active': False})
        
        # Create new configuration
        config_obj = NamecheapConfig(
            api_user=data['api_user'],
            api_key=data['api_key'],  # !!! PLAIN STORAGE — REPLACE BEFORE PROD
            username=data['username'],
            client_ip=data['client_ip'],
            is_sandbox=data.get('is_sandbox', True),
            is_active=True
        )
        
        db.session.add(config_obj)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Namecheap configuration saved successfully',
            'warning': 'API credentials are stored in plain text. Encrypt before production!'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to save Namecheap config: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to save configuration: {str(e)}'
        }), 500


@dns_bp.route('/namecheap/subdomain', methods=['POST'])
@login_required
def create_subdomain():
    """Create or update a subdomain DNS record"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['domain', 'subdomain', 'target']
        if not all(field in data for field in required_fields):
            return jsonify({
                'success': False,
                'error': 'Missing required fields: ' + ', '.join(required_fields)
            }), 400
        
        domain = data['domain'].strip().lower()
        subdomain = data['subdomain'].strip().lower()
        target = data['target'].strip()
        record_type = data.get('record_type', 'A').upper()
        ttl = data.get('ttl', config.DNS_DEFAULT_TTL)
        additional_records = data.get('additional_records', [])
        
        # Validate record type
        if record_type not in ['A', 'CNAME', 'TXT', 'MX']:
            return jsonify({
                'success': False,
                'error': 'Invalid record type. Supported: A, CNAME, TXT, MX'
            }), 400
        
        # Get DNS manager
        dns_manager = get_dns_manager()
        if not dns_manager:
            return jsonify({
                'success': False,
                'error': 'DNS manager not configured. Please configure Namecheap API settings.'
            }), 500
        
        # Create subdomain with additional records
        result = dns_manager.create_subdomain_with_records(
            domain, subdomain, target, additional_records
        )
        
        if result['success']:
            # Store record in database
            try:
                dns_record = DNSRecord(
                    domain=domain,
                    record_name=subdomain,
                    record_type=record_type,
                    record_value=target,
                    ttl=ttl,
                    created_by=session.get('username')
                )
                db.session.add(dns_record)
                
                # Store additional records
                for record in additional_records:
                    if record.get('name') and record.get('type') and record.get('value'):
                        additional_dns_record = DNSRecord(
                            domain=domain,
                            record_name=record['name'],
                            record_type=record['type'],
                            record_value=record['value'],
                            ttl=record.get('ttl', ttl),
                            mx_preference=record.get('mx_pref'),
                            created_by=session.get('username')
                        )
                        db.session.add(additional_dns_record)
                
                db.session.commit()
                
            except Exception as e:
                db.session.rollback()
                logger.warning(f"Failed to store DNS record in database: {str(e)}")
                # Don't fail the API call if database storage fails
        
        return jsonify({
            'success': result['success'],
            'subdomain': f"{subdomain}.{domain}",
            'target': target,
            'record_type': record_type,
            'ttl': ttl,
            'subdomain_created': result.get('subdomain_created', False),
            'additional_records': result.get('additional_records', []),
            'errors': result.get('errors', []),
            'message': f"Subdomain {subdomain}.{domain} configured successfully" if result['success'] else "Failed to create subdomain"
        })
        
    except Exception as e:
        logger.error(f"Failed to create subdomain: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to create subdomain: {str(e)}'
        }), 500


@dns_bp.route('/namecheap/records/<domain>', methods=['GET'])
@login_required
def get_domain_records(domain):
    """Get all DNS records for a domain"""
    try:
        dns_manager = get_dns_manager()
        if not dns_manager:
            return jsonify({
                'success': False,
                'error': 'DNS manager not configured'
            }), 500
        
        result = dns_manager.get_domain_records(domain)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Failed to get domain records: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to get domain records: {str(e)}'
        }), 500


@dns_bp.route('/namecheap/records', methods=['POST'])
@login_required
def add_dns_record():
    """Add or update a DNS record"""
    try:
        data = request.get_json()
        
        required_fields = ['domain', 'name', 'type', 'value']
        if not all(field in data for field in required_fields):
            return jsonify({
                'success': False,
                'error': 'Missing required fields: ' + ', '.join(required_fields)
            }), 400
        
        domain = data['domain'].strip().lower()
        record_name = data['name'].strip()
        record_type = data['type'].strip().upper()
        record_value = data['value'].strip()
        ttl = data.get('ttl', config.DNS_DEFAULT_TTL)
        mx_pref = data.get('mx_pref')
        
        dns_manager = get_dns_manager()
        if not dns_manager:
            return jsonify({
                'success': False,
                'error': 'DNS manager not configured'
            }), 500
        
        # Add or update record
        success = dns_manager.namecheap.add_or_update_record(
            domain, record_name, record_type, record_value, ttl, mx_pref
        )
        
        if success:
            # Store in database
            try:
                dns_record = DNSRecord(
                    domain=domain,
                    record_name=record_name,
                    record_type=record_type,
                    record_value=record_value,
                    ttl=ttl,
                    mx_preference=mx_pref,
                    created_by=session.get('username')
                )
                db.session.add(dns_record)
                db.session.commit()
            except Exception as e:
                logger.warning(f"Failed to store DNS record: {str(e)}")
        
        return jsonify({
            'success': success,
            'message': f"DNS record {record_name}.{domain} updated successfully" if success else "Failed to update DNS record"
        })
        
    except Exception as e:
        logger.error(f"Failed to add DNS record: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to add DNS record: {str(e)}'
        }), 500


@dns_bp.route('/namecheap/records', methods=['DELETE'])
@login_required
def delete_dns_record():
    """Delete a DNS record"""
    try:
        data = request.get_json()
        
        required_fields = ['domain', 'name']
        if not all(field in data for field in required_fields):
            return jsonify({
                'success': False,
                'error': 'Missing required fields: ' + ', '.join(required_fields)
            }), 400
        
        domain = data['domain'].strip().lower()
        record_name = data['name'].strip()
        record_type = data.get('type', '').strip().upper() or None
        
        dns_manager = get_dns_manager()
        if not dns_manager:
            return jsonify({
                'success': False,
                'error': 'DNS manager not configured'
            }), 500
        
        # Delete record
        success = dns_manager.namecheap.delete_record(domain, record_name, record_type)
        
        if success:
            # Mark as inactive in database
            try:
                query = DNSRecord.query.filter_by(domain=domain, record_name=record_name)
                if record_type:
                    query = query.filter_by(record_type=record_type)
                
                records = query.all()
                for record in records:
                    record.is_active = False
                
                db.session.commit()
            except Exception as e:
                logger.warning(f"Failed to update DNS record status: {str(e)}")
        
        return jsonify({
            'success': success,
            'message': f"DNS record {record_name}.{domain} deleted successfully" if success else "Failed to delete DNS record"
        })
        
    except Exception as e:
        logger.error(f"Failed to delete DNS record: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to delete DNS record: {str(e)}'
        }), 500


@dns_bp.route('/namecheap/verify-domain', methods=['POST'])
@login_required
def verify_domain_with_google():
    """Complete Google Site Verification workflow"""
    try:
        data = request.get_json()
        
        if 'domain' not in data:
            return jsonify({
                'success': False,
                'error': 'Domain field is required'
            }), 400
        
        domain = data['domain'].strip().lower()
        
        dns_manager = get_dns_manager()
        if not dns_manager:
            return jsonify({
                'success': False,
                'error': 'DNS manager not configured'
            }), 500
        
        # Check if Google verification is configured
        if not dns_manager.google_verification:
            return jsonify({
                'success': False,
                'error': 'Google Site Verification not configured. Please ensure Google API credentials are set up.',
                'help': 'Add siteverification scope to your Google API credentials'
            }), 500
        
        # Perform verification workflow
        result = dns_manager.verify_domain_with_google(domain)
        
        if result['success']:
            # Store verification result
            try:
                verification = GoogleVerification.query.filter_by(domain=domain).first()
                if not verification:
                    verification = GoogleVerification(domain=domain)
                
                verification.verification_token = result.get('verification_token')
                verification.is_verified = True
                verification.verified_at = datetime.utcnow()
                
                db.session.add(verification)
                db.session.commit()
                
            except Exception as e:
                logger.warning(f"Failed to store verification result: {str(e)}")
        
        return jsonify({
            'success': result['success'],
            'domain': domain,
            'verification_token': result.get('verification_token', ''),
            'message': result.get('message', result.get('error', 'Verification completed')),
            'error': result.get('error') if not result['success'] else None
        })
        
    except Exception as e:
        logger.error(f"Failed to verify domain: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to verify domain: {str(e)}'
        }), 500


@dns_bp.route('/google/verification-token', methods=['POST'])
@login_required
def get_google_verification_token():
    """Get Google verification token for a domain"""
    try:
        data = request.get_json()
        
        if 'domain' not in data:
            return jsonify({
                'success': False,
                'error': 'Domain field is required'
            }), 400
        
        domain = data['domain'].strip().lower()
        
        dns_manager = get_dns_manager()
        if not dns_manager or not dns_manager.google_verification:
            return jsonify({
                'success': False,
                'error': 'Google Site Verification not configured'
            }), 500
        
        # Get verification token
        token = dns_manager.google_verification.get_verification_token(domain)
        
        if token:
            # Store token for later use
            try:
                verification = GoogleVerification.query.filter_by(domain=domain).first()
                if not verification:
                    verification = GoogleVerification(domain=domain)
                
                verification.verification_token = token
                db.session.add(verification)
                db.session.commit()
                
            except Exception as e:
                logger.warning(f"Failed to store verification token: {str(e)}")
        
        return jsonify({
            'success': bool(token),
            'domain': domain,
            'verification_token': token,
            'message': 'Verification token generated successfully' if token else 'Failed to generate verification token'
        })
        
    except Exception as e:
        logger.error(f"Failed to get verification token: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to get verification token: {str(e)}'
        }), 500


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
                'created_at': record.created_at.isoformat(),
                'updated_at': record.updated_at.isoformat()
            })
        
        return jsonify({
            'success': True,
            'records': history,
            'total': len(history)
        })
        
    except Exception as e:
        logger.error(f"Failed to get DNS history: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to get DNS history: {str(e)}'
        }), 500


@dns_bp.route('/namecheap/domains', methods=['GET'])
@login_required
def get_namecheap_domains():
    """Fetch domains list from saved Namecheap account"""
    try:
        dns_manager = get_dns_manager()
        if not dns_manager:
            return jsonify({'success': False, 'error': 'DNS manager not configured'}), 500
        result = dns_manager.get_domains()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Failed to fetch Namecheap domains: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@dns_bp.route('/test-connection', methods=['POST'])
@login_required
def test_namecheap_connection():
    """Test Namecheap connection with provided or saved credentials"""
    try:
        data = request.get_json() or {}
        # Prefer request payload, fallback to saved config
        if all(k in data for k in ['api_user', 'api_key', 'username', 'client_ip']):
            cfg = {
                'api_user': data['api_user'],
                'api_key': data['api_key'],
                'username': data['username'],
                'client_ip': data['client_ip'],
                'sandbox': data.get('is_sandbox', True)
            }
        else:
            namecheap_config = NamecheapConfig.query.filter_by(is_active=True).first()
            if not namecheap_config:
                return jsonify({'success': False, 'error': 'No saved Namecheap configuration found'}), 400
            cfg = {
                'api_user': namecheap_config.api_user,
                'api_key': namecheap_config.api_key,
                'username': namecheap_config.username,
                'client_ip': namecheap_config.client_ip,
                'sandbox': namecheap_config.is_sandbox
            }
        
        # Attempt to fetch domains as a connectivity test
        api = NamecheapAPI(**cfg)
        domains = api.get_domains()
        return jsonify({'success': True, 'domains': domains, 'count': len(domains)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@dns_bp.route('/google/verified-domains', methods=['GET'])
@login_required
def get_verified_domains():
    """Get list of Google-verified domains"""
    try:
        dns_manager = get_dns_manager()
        if not dns_manager or not dns_manager.google_verification:
            return jsonify({
                'success': False,
                'error': 'Google Site Verification not configured'
            }), 500
        
        # Get verified sites from Google
        verified_sites = dns_manager.google_verification.list_verified_sites()
        
        # Get verification history from database
        db_verifications = GoogleVerification.query.filter_by(is_verified=True).all()
        
        db_domains = []
        for verification in db_verifications:
            db_domains.append({
                'domain': verification.domain,
                'verified_at': verification.verified_at.isoformat() if verification.verified_at else None,
                'verification_method': verification.verification_method
            })
        
        return jsonify({
            'success': True,
            'google_verified_sites': verified_sites,
            'database_verifications': db_domains
        })
        
    except Exception as e:
        logger.error(f"Failed to get verified domains: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to get verified domains: {str(e)}'
        }), 500


# Health check endpoint
@dns_bp.route('/health', methods=['GET'])
def health_check():
    """DNS module health check"""
    try:
        dns_manager = get_dns_manager()
        
        return jsonify({
            'success': True,
            'dns_manager_configured': dns_manager is not None,
            'google_verification_configured': dns_manager.google_verification is not None if dns_manager else False,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500