from dotenv import load_dotenv
load_dotenv()

import os

# Web App Settings
SECRET_KEY = os.environ.get('SECRET_KEY')
WHITELIST_TOKEN = os.environ.get('WHITELIST_TOKEN')

# IP Whitelist Configuration
ENABLE_IP_WHITELIST = os.environ.get('ENABLE_IP_WHITELIST', 'True').lower() == 'true'  # Default to True for security
ALLOW_ALL_IPS_IN_DEV = os.environ.get('ALLOW_ALL_IPS_IN_DEV', 'False').lower() == 'true'  # Default to False for security

# Database Configuration
# Use PostgreSQL for production (Ubuntu server), SQLite for local development
if os.environ.get('DATABASE_URL'):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
else:
    # Check if we're in production environment (Ubuntu server)
    if os.environ.get('FLASK_ENV') == 'production' or os.path.exists('/etc/nginx/sites-available/gbot'):
        # Production environment - use PostgreSQL
        SQLALCHEMY_DATABASE_URI = 'postgresql://gbot_user:gbot_password@localhost:5432/gbot_db'
    else:
        # Development environment - use SQLite
        db_path = os.path.join(os.path.dirname(__file__), 'instance', 'gbot.db')
        SQLALCHEMY_DATABASE_URI = f'sqlite:///{db_path}'
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Database Connection Pool Settings - MAXIMUM for 16GB RAM
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_size': 100,  # Maximum for high load (was 50)
    'pool_recycle': 3600,  # Recycle connections after 1 hour
    'pool_pre_ping': True,  # Validate connections before use
    'max_overflow': 200,  # Maximum overflow for burst traffic (was 100)
    'pool_timeout': 120,  # Longer timeout for high load (was 60)
    'connect_args': {
        'connect_timeout': 60,  # Longer connection timeout (was 30)
        'application_name': 'gbot_web_app'
    }
}

# Production Settings
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
FLASK_ENV = os.environ.get('FLASK_ENV', 'production')

# Security Settings
SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
PERMANENT_SESSION_LIFETIME = 3600  # 1 hour

# Timeout Settings for long-running operations
MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB
SEND_FILE_MAX_AGE_DEFAULT = 0

# Large User Base Settings (10k+ users)
LARGE_USER_OPERATION_TIMEOUT = 120  # 2 minutes for large user operations
USER_RETRIEVAL_PAGE_SIZE = 500  # Google's maximum per request
MAX_USERS_PER_OPERATION = 50000  # Support up to 50k users

# Logging
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')

# Google API Scopes (updated for admin role management)
SCOPES = [
    'https://www.googleapis.com/auth/admin.directory.user',
    'https://www.googleapis.com/auth/admin.directory.domain',
    'https://www.googleapis.com/auth/admin.directory.rolemanagement',
    'https://www.googleapis.com/auth/admin.directory.orgunit',
    'https://www.googleapis.com/auth/admin.directory.group'
]

# Debug - Check if values are loaded
if not SECRET_KEY:
    print("ERROR: SECRET_KEY not found in environment!")
if not WHITELIST_TOKEN:
    print("ERROR: WHITELIST_TOKEN not found in environment!")

# Production environment template
PRODUCTION_ENV_TEMPLATE = """
# GBot Web Application - Production Environment
SECRET_KEY={SECRET_KEY}
WHITELIST_TOKEN={WHITELIST_TOKEN}
DATABASE_URL=postgresql://gbot_user:{DB_PASSWORD}@localhost:5432/gbot_db
DEBUG=False
FLASK_ENV=production
LOG_LEVEL=INFO

# Google API Configuration
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# Production Settings
FLASK_ENV=production
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
"""
