# Chrome Automation Upgrade

This upgrade adds undetect Chrome driver automation to the GBot Web App, enabling automatic login using credentials retrieved from a remote server.

## New Features

### 1. Remote Account Retrieval
- Connects to server `162.55.213.50:22` using SSH
- Retrieves accounts from `/home/Accounts/accounts.json`
- Parses accounts in format: `username:password` (one per line)
- Stores accounts securely in session for Chrome automation

### 2. Chrome Automation
- Uses undetect-chromedriver for stealth browsing
- Automatically fills login forms with retrieved credentials
- Handles both Google-specific and generic login flows
- Provides real-time status updates and error handling

### 3. Enhanced OAuth Modal
- Added Chrome automation section to OAuth modal
- "Auto Login" button for automated authentication
- "Check Status" button to monitor Chrome state
- "Close Chrome" button to clean up resources

## Installation

1. Install the new dependency:
```bash
pip install undetected-chromedriver==3.5.5
```

2. Run the test script to verify installation:
```bash
python test_chrome_automation.py
```

## Usage

### Step 1: Retrieve Accounts
1. Navigate to the dashboard
2. Click "Retrieve Accounts" button
3. System will connect to server and fetch account credentials
4. Success message shows number of accounts retrieved

### Step 2: Select Account
1. Choose an account from the dropdown
2. Click "Authenticate Selected" to generate OAuth URL
3. OAuth modal will appear with Chrome automation options

### Step 3: Chrome Automation
1. In the OAuth modal, click "Auto Login"
2. Chrome will automatically:
   - Navigate to OAuth URL
   - Fill in username and password
   - Complete the login process
3. Monitor status in the Chrome automation section

## API Endpoints

### `/api/retrieve-accounts` (POST)
Retrieves accounts from remote server
- **Response**: List of accounts with username/password

### `/api/chrome-login` (POST)
Performs Chrome automation login
- **Parameters**: `oauth_url`, `account_name`
- **Response**: Login success/failure status

### `/api/chrome-status` (GET)
Gets current Chrome driver status
- **Response**: Current page information

### `/api/close-chrome` (POST)
Closes Chrome driver instance
- **Response**: Success/failure status

## Configuration

Server connection details are configured in `chrome_automation.py`:
```python
SERVER_ADDRESS = '162.55.213.50'
SERVER_PORT = 22
USERNAME = 'root'
PASSWORD = 'GkNqzZVbyRmgES46'
REMOTE_DIR = '/home/Accounts/accounts.json'
```

## Security Features

- Credentials are never logged or exposed
- SSH connection uses timeout and error handling
- Chrome driver runs in undetect mode
- Session-based credential storage
- Graceful error handling and cleanup

## Error Handling

- Server connection failures
- Missing or malformed account files
- Chrome driver initialization errors
- Login form detection failures
- Network timeouts and errors

## Troubleshooting

### Common Issues

1. **Chrome driver fails to start**
   - Ensure Chrome browser is installed
   - Check system permissions
   - Verify undetect-chromedriver installation

2. **Server connection fails**
   - Verify server is reachable
   - Check SSH credentials
   - Ensure accounts.json file exists

3. **Login automation fails**
   - Check if login form elements are detected
   - Verify account credentials are correct
   - Monitor Chrome status for errors

### Debug Commands

```bash
# Test all functionality
python test_chrome_automation.py

# Check Chrome driver status
curl -X GET http://localhost:5000/api/chrome-status

# Close Chrome driver
curl -X POST http://localhost:5000/api/close-chrome
```

## Files Modified

- `requirements.txt` - Added undetect-chromedriver dependency
- `chrome_automation.py` - New Chrome automation module
- `app.py` - Added new API endpoints
- `templates/dashboard.html` - Enhanced OAuth modal with Chrome automation
- `test_chrome_automation.py` - Test script for verification

## Browser Compatibility

- Chrome/Chromium browser required
- Compatible with Chrome versions 90+
- Works on Windows, macOS, and Linux
- Headless mode supported for server environments
