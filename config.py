from dotenv import load_dotenv
load_dotenv()

import os

# SFTP Configuration (same as your V13)
SERVER_ADDRESS = '159.89.19.179'
SERVER_PORT = 22
USERNAME = 'root'
PASSWORD = os.environ.get('SFTP_PASSWORD')
REMOTE_DIR = '/home/Google_Apiss/'
REMOTE_ALT_DIR = '/home/brightmindscampuss/'

# Web App Settings
SECRET_KEY = os.environ.get('SECRET_KEY')
WHITELIST_TOKEN = os.environ.get('WHITELIST_TOKEN')

# Google API Scopes (same as V13)
SCOPES = [
    'https://www.googleapis.com/auth/admin.directory.user',
    'https://www.googleapis.com/auth/admin.directory.domain'
]

# Debug - Check if values are loaded
if not PASSWORD:
    print("ERROR: SFTP_PASSWORD not found in environment!")
if not SECRET_KEY:
    print("ERROR: SECRET_KEY not found in environment!")
if not WHITELIST_TOKEN:
    print("ERROR: WHITELIST_TOKEN not found in environment!")