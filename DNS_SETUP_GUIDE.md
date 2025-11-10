# DNS Automation Module Setup Guide

This guide explains how to set up and configure the DNS automation module for GBot Web App.

## Overview

The DNS module provides:
- **Namecheap API Integration**: Create, update, and delete DNS records
- **Subdomain Management**: Automated subdomain creation and management
- **Google Site Verification**: Complete verification workflow
- **DNS History Tracking**: Track all DNS changes with audit trail
- **Production-Ready**: Error handling, logging, and safe record merging

## Prerequisites

1. **Namecheap Account** with API access
2. **Google Cloud Project** with Site Verification API enabled
3. **GBot Web App** running (Flask application)

## Step 1: Namecheap API Setup

### Enable API Access
1. Log in to your Namecheap account
2. Go to **Profile** → **Tools** → **Business & Dev Tools** → **API Access**
3. Enable API access and whitelist your server IP
4. Note down your API credentials:
   - API User (usually your username)
   - API Key (generated token)
   - Username (your account username)
   - Client IP (your server's IP address)

### Get API Credentials
```bash
# Your Namecheap API details (example)
API_USER=your_username
API_KEY=your_api_key_here
USERNAME=your_username
CLIENT_IP=your.server.ip.address
```

## Step 2: Google Site Verification API Setup

### Enable the API
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Select your project (or create a new one)
3. Navigate to **APIs & Services** → **Library**
4. Search for "Site Verification API"
5. Click **Enable**

### Update API Scopes
The GBot app needs the following scope added to your existing Google API setup:
```
https://www.googleapis.com/auth/siteverification
```

Add this scope to your existing Google API configuration.

## Step 3: Environment Configuration

Add the following environment variables to your `.env` file:

```bash
# Namecheap API Configuration
# !!! ENCRYPT THESE VALUES IN PRODUCTION !!!
NAMECHEAP_API_USER=your_namecheap_api_user
NAMECHEAP_API_KEY=your_namecheap_api_key
NAMECHEAP_USERNAME=your_namecheap_username
NAMECHEAP_CLIENT_IP=your_whitelisted_ip
NAMECHEAP_SANDBOX=False

# DNS Configuration
DNS_DEFAULT_TTL=1800
DNS_VERIFICATION_TTL=300
DNS_PROPAGATION_WAIT=10
```

### Sandbox vs Production
- Set `NAMECHEAP_SANDBOX=True` for testing
- Set `NAMECHEAP_SANDBOX=False` for production
- Sandbox URL: `api.sandbox.namecheap.com`
- Production URL: `api.namecheap.com`

## Step 4: Database Migration

Run the database migration to create DNS tables:

```bash
# Navigate to your GBot directory
cd /path/to/gbot-web-app

# Run the migration script
python3 create_dns_tables.py
```

This creates the following tables:
- `namecheap_config` - API configuration storage
- `dns_record` - DNS records history and tracking
- `google_verification` - Google Site Verification tracking

## Step 5: Install Dependencies

Install additional Python packages:

```bash
pip install lxml==4.9.3
```

Or update from requirements.txt:
```bash
pip install -r requirements.txt
```

## Step 6: Restart Application

Restart your GBot application:

```bash
# Using systemd service
sudo systemctl restart gbot

# Or using Gunicorn directly
pkill -f gunicorn
gunicorn -c gunicorn.conf.py app:app

# Or for development
python3 app.py
```

## Usage

### Access DNS Manager
1. Log in to GBot Web App
2. Go to Dashboard
3. Click "Open DNS Manager" card
4. Configure Namecheap API settings

### API Endpoints

The module provides RESTful API endpoints:

#### Configuration
- `GET /api/dns/namecheap/config` - Get current configuration
- `POST /api/dns/namecheap/config` - Set API configuration

#### DNS Management
- `POST /api/dns/namecheap/subdomain` - Create subdomain
- `GET /api/dns/namecheap/records/{domain}` - Get domain records
- `POST /api/dns/namecheap/records` - Add/update DNS record
- `DELETE /api/dns/namecheap/records` - Delete DNS record

#### Google Verification
- `POST /api/dns/namecheap/verify-domain` - Complete verification workflow
- `POST /api/dns/google/verification-token` - Get verification token only
- `GET /api/dns/google/verified-domains` - List verified domains

#### History & Monitoring
- `GET /api/dns/records/history` - Get DNS change history
- `GET /api/dns/health` - DNS module health check

### Example API Calls

#### Create a Subdomain
```bash
curl -X POST http://your-domain/api/dns/namecheap/subdomain \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "subdomain": "api",
    "target": "192.168.1.100",
    "record_type": "A",
    "ttl": 1800
  }'
```

#### Verify Domain with Google
```bash
curl -X POST http://your-domain/api/dns/namecheap/verify-domain \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com"
  }'
```

## Security Considerations

⚠️ **IMPORTANT SECURITY NOTES**

### API Keys Storage
The current implementation stores API keys in **plain text**. For production:

1. **Encrypt API keys** in the database
2. **Use environment variables** for sensitive data
3. **Implement key rotation** policies
4. **Use secrets management** (AWS Secrets Manager, Azure Key Vault, etc.)

### Network Security
- Ensure your server IP is **whitelisted** in Namecheap
- Use **HTTPS** for all API communications
- Implement **rate limiting** for API endpoints
- **Monitor API usage** for suspicious activity

### Access Control
- DNS operations require **authenticated sessions**
- Implement **role-based access** control
- **Audit all DNS changes** (already implemented)
- **Log all API requests** for security monitoring

## Troubleshooting

### Common Issues

#### 1. API Authentication Failed
```
Error: Namecheap API Error: Invalid request IP
```
**Solution**: Ensure your server IP is whitelisted in Namecheap account

#### 2. DNS Records Not Updating
```
Error: setHosts operation failed
```
**Solution**: Check domain ownership and API permissions

#### 3. Google Verification Failed
```
Error: Google Site Verification not configured
```
**Solution**: Ensure Site Verification API is enabled and scopes are correct

#### 4. Database Errors
```
Error: relation "namecheap_config" does not exist
```
**Solution**: Run the database migration script

### Debug Mode

Enable debug logging by setting:
```bash
export LOG_LEVEL=DEBUG
```

### Testing API Endpoints

Test the health check endpoint:
```bash
curl http://your-domain/api/dns/health
```

Expected response:
```json
{
  "success": true,
  "dns_manager_configured": true,
  "google_verification_configured": true,
  "timestamp": "2024-01-01T12:00:00.000000"
}
```

## Production Deployment

### Security Checklist
- [ ] Encrypt API keys in database
- [ ] Use HTTPS with valid SSL certificates
- [ ] Implement proper backup strategies
- [ ] Set up monitoring and alerting
- [ ] Configure log rotation
- [ ] Implement rate limiting
- [ ] Review and test disaster recovery

### Performance Optimization
- [ ] Enable database connection pooling
- [ ] Implement caching for DNS queries
- [ ] Set up CDN for static assets
- [ ] Monitor API response times
- [ ] Optimize database queries

### Monitoring
- [ ] Set up health checks
- [ ] Monitor API error rates
- [ ] Track DNS propagation times
- [ ] Alert on verification failures
- [ ] Monitor database performance

## Support

For technical support:
1. Check the application logs: `logs/gbot.log`
2. Review DNS history in the web interface
3. Test API endpoints manually
4. Check Namecheap API status
5. Verify Google API quotas and limits

## License

This DNS automation module is part of the GBot Web App open-source project.