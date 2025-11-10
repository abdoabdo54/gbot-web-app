from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from flask import Blueprint, current_app, jsonify, request, session

from database import db, NamecheapConfig
from dns_logs import add_log_entry, get_recent_logs
from namecheap_client import NamecheapClient, NamecheapAPIError
import config as app_config
from google_site_verification import get_dns_txt_token, verify_domain_with_dns


dns_bp = Blueprint("dns_api", __name__)


# ---- Auth guard for all DNS endpoints ----
@dns_bp.before_request
def require_login():
    # Minimal auth integration: rely on session values set by existing auth
    if not session.get('user'):
        return jsonify({"success": False, "error": "Authentication required"}), 401


# ---- Helpers ----

def _active_config_dict() -> Dict[str, Any]:
    cfg = (
        NamecheapConfig.query.filter_by(is_active=True)
        .order_by(NamecheapConfig.updated_at.desc())
        .first()
    )
    if cfg:
        api_url = os.environ.get(
            "NAMECHEAP_API_URL",
            "https://api.sandbox.namecheap.com/xml.response" if cfg.is_sandbox else "https://api.namecheap.com/xml.response",
        )
        return {
            "api_user": cfg.api_user,
            "api_key": cfg.api_key,
            "username": cfg.username,
            "client_ip": cfg.client_ip,
            "api_url": api_url,
        }
    # Env fallback
    api_url = os.environ.get("NAMECHEAP_API_URL", app_config.NAMECHEAP_API_URL)
    if app_config.NAMECHEAP_SANDBOX:
        api_url = "https://api.sandbox.namecheap.com/xml.response"
    if all(
        [
            app_config.NAMECHEAP_API_USER,
            app_config.NAMECHEAP_API_KEY,
            app_config.NAMECHEAP_USERNAME,
            app_config.NAMECHEAP_CLIENT_IP,
        ]
    ):
        return {
            "api_user": app_config.NAMECHEAP_API_USER,
            "api_key": app_config.NAMECHEAP_API_KEY,
            "username": app_config.NAMECHEAP_USERNAME,
            "client_ip": app_config.NAMECHEAP_CLIENT_IP,
            "api_url": api_url,
        }
    return {}


def _client() -> NamecheapClient:
    cfg = _active_config_dict()
    if not cfg:
        raise NamecheapAPIError("Namecheap API not configured. Save configuration first.")
    return NamecheapClient(
        api_user=cfg["api_user"],
        api_key=cfg["api_key"],
        username=cfg["username"],
        client_ip=cfg["client_ip"],
        api_url=cfg["api_url"],
    )


def _is_our_dns(domain: str, client: Optional[NamecheapClient] = None) -> bool:
    try:
        c = client or _client()
        domains = c.get_domains()
        for d in domains:
            if d.get("Domain") == domain:
                return bool(d.get("IsOurDNS", False))
    except Exception:
        pass
    return False


# ---- Routes ----

@dns_bp.route("/api/dns/namecheap/config", methods=["GET", "POST"])
def namecheap_config_handler():
    if request.method == "GET":
        cfg = (
            NamecheapConfig.query.filter_by(is_active=True)
            .order_by(NamecheapConfig.updated_at.desc())
            .first()
        )
        if cfg:
            return jsonify(
                {
                    "configured": True,
                    "config": {
                        "api_user": cfg.api_user,
                        "username": cfg.username,
                        "client_ip": cfg.client_ip,
                        "is_sandbox": cfg.is_sandbox,
                    },
                }
            )
        # Env fallback
        env_present = all(
            [
                app_config.NAMECHEAP_API_USER,
                app_config.NAMECHEAP_USERNAME,
                app_config.NAMECHEAP_CLIENT_IP,
            ]
        )
        return jsonify(
            {
                "configured": env_present,
                "config": {
                    "api_user": app_config.NAMECHEAP_API_USER,
                    "username": app_config.NAMECHEAP_USERNAME,
                    "client_ip": app_config.NAMECHEAP_CLIENT_IP,
                    "is_sandbox": app_config.NAMECHEAP_SANDBOX,
                },
            }
        )

    # POST -> save
    data = request.get_json(force=True)
    required = ["api_user", "api_key", "username", "client_ip"]
    missing = [k for k in required if not data.get(k)]
    if missing:
        return jsonify({"success": False, "error": f"Missing fields: {', '.join(missing)}"}), 400

    try:
        NamecheapConfig.query.update({NamecheapConfig.is_active: False})
        cfg = NamecheapConfig(
            api_user=data["api_user"],
            api_key=data["api_key"],  # !!! PLAIN STORAGE — REPLACE BEFORE PROD
            username=data["username"],
            client_ip=data["client_ip"],
            is_sandbox=bool(data.get("is_sandbox", False)),
            is_active=True,
        )
        db.session.add(cfg)
        db.session.commit()
        add_log_entry("save_config", status="success", message="Saved Namecheap API configuration")
        return jsonify({"success": True, "warning": "# !!! PLAIN STORAGE — REPLACE BEFORE PROD"})
    except Exception as e:
        db.session.rollback()
        add_log_entry("save_config", status="error", message=str(e))
        return jsonify({"success": False, "error": str(e)}), 500


@dns_bp.route("/api/dns/test-connection", methods=["POST"])
def test_connection():
    data = request.get_json(force=True)
    try:
        client = NamecheapClient(
            api_user=data.get("api_user"),
            api_key=data.get("api_key"),
            username=data.get("username"),
            client_ip=data.get("client_ip"),
            api_url=(
                "https://api.sandbox.namecheap.com/xml.response"
                if data.get("is_sandbox")
                else os.environ.get("NAMECHEAP_API_URL", "https://api.namecheap.com/xml.response")
            ),
        )
        _ = client.get_domains()
        add_log_entry("test_connection", status="success", message="Namecheap connection OK")
        return jsonify({"success": True})
    except Exception as e:
        add_log_entry("test_connection", status="error", message=str(e))
        return jsonify({"success": False, "error": str(e)}), 400


@dns_bp.route("/api/dns/namecheap/domains", methods=["GET"])
def list_domains():
    try:
        client = _client()
        domains = client.get_domains()
        add_log_entry("getList", status="success", message=f"Fetched {len(domains)} domains")
        return jsonify({"success": True, "domains": domains})
    except Exception as e:
        add_log_entry("getList", status="error", message=str(e))
        return jsonify({"success": False, "error": str(e)}), 400


@dns_bp.route("/api/dns/namecheap/hosts", methods=["GET"])
def get_hosts():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"success": False, "error": "Missing domain"}), 400
    try:
        client = _client()
        if not _is_our_dns(domain, client):
            return jsonify({"success": False, "error": "Domain is not using our DNS at Namecheap"}), 403
        hosts = client.get_hosts(domain)
        add_log_entry("getHosts", domain=domain, status="success", message=f"Fetched {len(hosts)} hosts")
        return jsonify({"success": True, "hosts": hosts})
    except Exception as e:
        add_log_entry("getHosts", domain=domain, status="error", message=str(e))
        return jsonify({"success": False, "error": str(e)}), 400


@dns_bp.route("/api/dns/namecheap/record", methods=["POST"])
def upsert_record():
    data = request.get_json(force=True)
    for k in ["domain", "host", "type", "value"]:
        if not data.get(k):
            return jsonify({"success": False, "error": f"Missing field: {k}"}), 400
    ttl = int(data.get("ttl", current_app.config.get("DNS_DEFAULT_TTL", 1800)))
    domain = data["domain"]
    try:
        client = _client()
        if not _is_our_dns(domain, client):
            return jsonify({"success": False, "error": "Domain is not using our DNS at Namecheap"}), 403
        changed, new_hosts = client.add_or_update_record(
            domain=domain,
            host=data["host"],
            rtype=data["type"],
            value=data["value"],
            ttl=ttl,
        )
        add_log_entry(
            "setHosts",
            domain=domain,
            status="success",
            message=f"Record {data['host']} {data['type']} {'updated' if changed else 'no-change'}",
            target=data["host"],
        )
        return jsonify({"success": True, "changed": changed, "hosts": new_hosts})
    except Exception as e:
        add_log_entry("setHosts", domain=domain, status="error", message=str(e))
        return jsonify({"success": False, "error": str(e)}), 400


@dns_bp.route("/api/dns/namecheap/verify-domain", methods=["POST"])
def verify_domain():
    data = request.get_json(force=True)
    domain = data.get("domain", "").strip()
    host = (data.get("host", "@").strip() or "@")
    auto_verify = bool(data.get("auto_verify", False))

    if not domain:
        return jsonify({"success": False, "error": "Missing domain"}), 400

    try:
        # 1) Obtain token from Google
        service_account_path = current_app.config.get("GOOGLE_SERVICE_ACCOUNT_PATH")
        token_resp = get_dns_txt_token(service_account_path, domain)
        token = token_resp.get("token")
        if not token:
            raise ValueError("Failed to obtain verification token from Google")
        add_log_entry("getToken", domain=domain, status="success", message="Obtained DNS TXT token")

        # 2) Apply TXT in Namecheap
        client = _client()
        if not _is_our_dns(domain, client):
            return jsonify({"success": False, "error": "Domain is not using our DNS at Namecheap"}), 403
        ttl = int(current_app.config.get("DNS_VERIFICATION_TTL", 300))
        client.add_or_update_txt(domain, host, token, ttl=ttl)
        add_log_entry("setHosts", domain=domain, status="success", message=f"Applied TXT token to host '{host}'", target=host)

        result: Dict[str, Any] = {"success": True, "token": token}

        # 3) Optionally verify
        if auto_verify:
            verify_resp = verify_domain_with_dns(service_account_path, domain)
            add_log_entry("insert", domain=domain, status="success", message="Verification attempted")
            result["verification"] = verify_resp

        return jsonify(result)
    except Exception as e:
        add_log_entry("verify", domain=domain, status="error", message=str(e))
        return jsonify({"success": False, "error": str(e)}), 400


@dns_bp.route("/api/dns/namecheap/logs", methods=["GET"])
def logs():
    limit = int(request.args.get("limit", 50))
    return jsonify({"success": True, "logs": get_recent_logs(limit)})
