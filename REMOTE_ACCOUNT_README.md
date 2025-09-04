# GBot Web App - Remote Account Management Upgrade

This upgrade adds remote account retrieval and Chrome automation capabilities to the GBot Web App, allowing for automated login to Google accounts using username/password authentication.

## New Features

### 🔄 Remote Account Retrieval
- **Server Connection**: Connects to remote server via SFTP to retrieve account credentials
- **Automatic Parsing**: Parses accounts from `/home/Accounts/accounts.json` file
- **Format Support**: Supports `account:password` format (one per line)
- **Session Storage**: Stores retrieved accounts in session for use across the application

### 🤖 Chrome Automation
- **Undetect Chrome Driver**: Uses undetected-chromedriver for stealth automation
- **Google Login Automation**: Automatically fills username/password and handles OAuth flow
- **Concurrency Control**: Supports multiple concurrent login processes
- **Error Handling**: Graceful error handling for login failures and timeouts

### 🎯 Enhanced OAuth Flow
- **Chrome Integration**: "Login with Chrome" button in OAuth modal
- **Automatic Authorization**: Automatically handles OAuth authorization after login
- **Code Extraction**: Extracts authorization codes from successful logins
- **Seamless Integration**: Works with existing OAuth flow

## Server Configuration

The application connects to the following server configuration:

```python
SERVER_ADDRESS = '162.55.213.50'
SERVER_PORT = 22
USERNAME = 'root'
PASSWORD = 'GkNqzZVbyRmgES46'
REMOTE_DIR = '/home/Accounts/accounts.json'
```

## Account File Format

The remote accounts file should be in the following format:

```
admin@domain1.com:password123
user@domain2.com:password456
admin@domain3.com:password789
```

- One account per line
- Format: `email:password`
- No headers or comments (lines starting with # are ignored)

## New UI Components

### Remote Account Management Section
- **Retrieve Accounts**: Downloads accounts from remote server
- **Delete Retrieved**: Clears retrieved accounts from session
- **Login (Selected)**: Login to currently selected account
- **Login (Multiple)**: Login to multiple accounts with concurrency control

### Account Field
- **Flexible Input**: Text area for displaying retrieved accounts
- **Manual Entry**: Support for manual account entry
- **Format Validation**: Validates account:password format

### Concurrency Control
- **Max Concurrent Logins**: Spinbox to control concurrent processes (1-10)
- **Queue Management**: Background processing of login queue
- **Status Monitoring**: Real-time status updates for login processes

## API Endpoints

### New Endpoints
- `POST /api/retrieve-remote-accounts` - Retrieve accounts from server
- `POST /api/login-selected-account` - Login to selected account
- `POST /api/login-multiple-accounts` - Login to multiple accounts
- `POST /api/get-login-status` - Get login queue status
- `POST /api/clear-retrieved-accounts` - Clear retrieved accounts

### Enhanced Endpoints
- `POST /api/authenticate` - Now supports Chrome automation integration

## Installation

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Test Installation**:
   ```bash
   python test_remote_accounts.py
   ```

3. **Start Application**:
   ```bash
   python app.py
   ```

## Usage Workflow

### Basic Workflow
1. **Retrieve Accounts**: Click "Retrieve Accounts" to download from server
2. **Select Account**: Choose an account from the dropdown
3. **Authenticate**: Click "Authenticate Selected" to generate OAuth URL
4. **Chrome Login**: Click "Login with Chrome" in OAuth modal
5. **Complete OAuth**: Authorization code is automatically extracted and used

### Multiple Account Workflow
1. **Retrieve Accounts**: Download accounts from server
2. **Set Concurrency**: Adjust max concurrent logins (default: 3)
3. **Authenticate**: Generate OAuth URL for any account
4. **Multiple Login**: Click "Login (Multiple)" to process all accounts
5. **Monitor Progress**: Watch status updates for queue processing

## Security Features

### Credential Protection
- **No Logging**: Credentials are never logged to console or files
- **Session Storage**: Credentials stored only in session memory
- **Automatic Cleanup**: Session cleared on logout or timeout
- **SFTP Security**: Secure file transfer with SSH authentication

### Chrome Security
- **Undetect Mode**: Chrome runs in stealth mode to avoid detection
- **Isolated Process**: Each Chrome instance runs in isolated process
- **Automatic Cleanup**: Browser instances automatically closed after use
- **Error Isolation**: Failed logins don't affect other processes

## Error Handling

### Server Connection Errors
- **Connection Timeout**: Graceful handling of server unavailability
- **Authentication Failure**: Clear error messages for invalid credentials
- **File Not Found**: Handles missing or malformed account files
- **Network Issues**: Retry logic for temporary network problems

### Chrome Automation Errors
- **Driver Setup**: Handles Chrome driver installation issues
- **Login Failures**: Detailed error messages for authentication problems
- **Timeout Handling**: Configurable timeouts for page loading
- **Element Not Found**: Graceful handling of missing page elements

## Troubleshooting

### Common Issues

1. **Chrome Driver Not Found**:
   - Install Chrome browser
   - Ensure Chrome is in PATH
   - Check undetected-chromedriver installation

2. **Server Connection Failed**:
   - Verify server IP and credentials
   - Check network connectivity
   - Ensure SSH access is enabled

3. **Login Failures**:
   - Verify account credentials in server file
   - Check for 2FA requirements
   - Ensure account is not locked

4. **OAuth Issues**:
   - Verify OAuth URL generation
   - Check redirect URI configuration
   - Ensure proper scopes are requested

### Debug Mode
Enable debug logging by setting environment variable:
```bash
export DEBUG=True
```

## Performance Considerations

### Concurrency Limits
- **Default**: 3 concurrent logins
- **Maximum**: 10 concurrent logins
- **Recommendation**: Start with 3, increase based on system performance

### Memory Usage
- **Chrome Instances**: Each Chrome instance uses ~100-200MB RAM
- **Session Storage**: Retrieved accounts stored in memory
- **Cleanup**: Automatic cleanup of completed processes

### Network Usage
- **SFTP Transfer**: Minimal bandwidth for account file download
- **Chrome Automation**: Standard web traffic for login process
- **OAuth Flow**: Standard OAuth 2.0 traffic

## Future Enhancements

### Planned Features
- **Account Validation**: Pre-validate accounts before login attempts
- **Batch Processing**: Support for large account files
- **Progress Tracking**: Real-time progress bars for multiple logins
- **Result Export**: Export login results to CSV/JSON
- **Retry Logic**: Automatic retry for failed logins
- **Proxy Support**: Support for proxy servers in Chrome automation

### Configuration Options
- **Custom Server**: Configurable server settings via environment variables
- **Chrome Options**: Customizable Chrome driver options
- **Timeout Settings**: Configurable timeouts for different operations
- **Logging Levels**: Adjustable logging verbosity

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review application logs in `logs/gbot.log`
3. Run the test script: `python test_remote_accounts.py`
4. Check server connectivity and account file format

## Changelog

### Version 1.0.0 (Current)
- ✅ Remote account retrieval via SFTP
- ✅ Chrome automation with undetected-chromedriver
- ✅ Multiple account login with concurrency control
- ✅ Enhanced OAuth flow integration
- ✅ Flexible account field and UI controls
- ✅ Comprehensive error handling and logging
