"""
Google Site Verification helper using official API.
"""
from __future__ import annotations

from typing import Dict, Optional

from googleapiclient.discovery import build
from google.oauth2 import service_account


def _build_credentials(service_account_path: str, scopes: Optional[list] = None):
    if not service_account_path:
        raise ValueError("GOOGLE_SERVICE_ACCOUNT_PATH is not configured. Provide a service account JSON path.")
    if scopes is None:
        scopes = [
            "https://www.googleapis.com/auth/siteverification",
        ]
    credentials = service_account.Credentials.from_service_account_file(service_account_path, scopes=scopes)
    return credentials


def get_dns_txt_token(service_account_path: str, domain: str) -> Dict:
    """Get DNS TXT token for domain verification."""
    creds = _build_credentials(service_account_path)
    service = build("siteVerification", "v1", credentials=creds, cache_discovery=False)

    body = {
        "site": {
            "type": "INET_DOMAIN",
            "identifier": domain,
        },
        "verificationMethod": "DNS_TXT",
    }
    token_resp = service.webResource().getToken(body=body).execute()
    return {
        "status": "success",
        "token": token_resp.get("token"),
        "method": token_resp.get("method"),
    }


def verify_domain_with_dns(service_account_path: str, domain: str, method: str = "DNS_TXT") -> Dict:
    """Attempt to verify a domain via DNS method."""
    creds = _build_credentials(service_account_path)
    service = build("siteVerification", "v1", credentials=creds, cache_discovery=False)

    body = {
        "site": {
            "type": "INET_DOMAIN",
            "identifier": domain,
        }
    }
    verification = service.webResource().insert(verificationMethod=method, body=body).execute()
    return {
        "status": "success",
        "verification": verification,
    }
