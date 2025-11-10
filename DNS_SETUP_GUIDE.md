# DNS & Google Verification Module - Setup Guide

This guide explains how to configure and operate the DNS Manager in GBot Web App using Namecheap and Google Site Verification.

## 1) Prerequisites
- A Namecheap account with API access enabled
- Whitelisted server public IPv4 in Namecheap → Profile → Tools → API Access
- Google Cloud Project with Site Verification API enabled
- Service Account JSON (optional) for verification

## 2) Environment Variables (optional fallback)
Set these if you don’t want to save config via UI.

```
NAMECHEAP_API_USER=...
NAMECHEAP_API_KEY=...
NAMECHEAP_USERNAME=...
NAMECHEAP_CLIENT_IP=...
NAMECHEAP_SANDBOX=False

# Google (optional)
GOOGLE_SERVICE_ACCOUNT_PATH=/path/to/service_account.json

# DNS defaults
DNS_DEFAULT_TTL=1800
DNS_VERIFICATION_TTL=300
DNS_PROPAGATION_WAIT=10
```

## 3) Install dependencies
```
pip install -r requirements.txt
```

## 4) Create tables
```
python3 create_dns_tables.py
```

## 5) Start GBot and open DNS Manager
- Log in to GBot Web App
- Open “DNS Manager” in the header
- Save Namecheap config (⚠️ stored in plain text — replace before prod)
- Click “Fetch Domains”, select a domain using Namecheap DNS (IsOurDNS=true)
- Manage records or run Google verification

## 6) REST API Summary
- POST /api/dns/namecheap/config
- GET  /api/dns/namecheap/config
- GET  /api/dns/namecheap/domains
- GET  /api/dns/namecheap/hosts?domain=example.com
- POST /api/dns/namecheap/record
- POST /api/dns/namecheap/verify-domain
- GET  /api/dns/logs

## 7) Troubleshooting
- Namecheap ERROR: ensure ClientIp is the server’s public IPv4 and whitelisted; verify Sandbox flag.
- ApiUser/UserName should often match exactly.
- Domain must use Namecheap DNS (IsOurDNS=true) for updates.
- Check logs: logs/dns_module.log or UI’s Live Debug Log.
