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
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://user:password@localhost/gbot_db')
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Production Settings
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
FLASK_ENV = os.environ.get('FLASK_ENV', 'production')

# Security Settings
SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
PERMANENT_SESSION_LIFETIME = 3600  # 1 hour

# Logging
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')

# Google API Scopes (same as V13)
SCOPES = [
    'https://www.googleapis.com/auth/admin.directory.user',
    'https://www.googleapis.com/auth/admin.directory.domain'
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
DATABASE_URL=postgresql://gbot_user:{DB_PASSWORD}@localhost/gbot_db
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
