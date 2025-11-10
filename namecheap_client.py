"""
Namecheap API Client for DNS management.

Implements:
- get_domains()
- get_hosts(domain)
- set_hosts(domain, hosts)
- add_or_update_record(domain, host, rtype, value, ttl)
- add_or_update_txt(domain, host, value, ttl)

Uses requests and xml.etree.ElementTree for XML parsing.
"""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

import requests


class NamecheapAPIError(Exception):
    """Exception class for Namecheap API errors."""


class NamecheapClient:
    """Simple Namecheap API client.

    Parameters
    ----------
    api_user : str
        Namecheap API user.
    api_key : str
        Namecheap API key.
    username : str
        Namecheap username (often same as api_user).
    client_ip : str
        Whitelisted client IP for Namecheap API access.
    api_url : str
        Namecheap API base URL, e.g., https://api.namecheap.com/xml.response (or sandbox URL).
    """

    def __init__(
        self,
        api_user: str,
        api_key: str,
        username: str,
        client_ip: str,
        api_url: str = "https://api.namecheap.com/xml.response",
        timeout: int = 30,
    ) -> None:
        self.api_user = api_user
        self.api_key = api_key
        self.username = username
        self.client_ip = client_ip
        self.api_url = api_url
        self.timeout = timeout

    def _request(self, command: str, params: Optional[Dict[str, str]] = None) -> ET.Element:
        data = {
            "ApiUser": self.api_user,
            "ApiKey": self.api_key,
            "UserName": self.username,
            "ClientIp": self.client_ip,
            "Command": command,
        }
        if params:
            data.update(params)

        logging.debug(
            "Namecheap request: %s params=%s",
            command,
            {k: v for k, v in data.items() if k != "ApiKey"},
        )
        try:
            resp = requests.get(self.api_url, params=data, timeout=self.timeout)
        except Exception as e:
            raise NamecheapAPIError(f"Network error calling Namecheap: {e}")

        if resp.status_code != 200:
            raise NamecheapAPIError(f"HTTP {resp.status_code} from Namecheap: {resp.text[:200]}")

        try:
            root = ET.fromstring(resp.text)
        except ET.ParseError as pe:
            raise NamecheapAPIError(f"Invalid XML from Namecheap: {pe}\nBody: {resp.text[:300]}")

        status = root.attrib.get("Status", "ERROR")
        if status != "OK":
            # Try to extract error message
            errors = root.findall(".//Errors/Error")
            msg = "; ".join(e.text or "" for e in errors) or "Unknown Namecheap error"
            raise NamecheapAPIError(msg)

        return root

    def get_domains(self) -> List[Dict[str, str]]:
        """Return list of domains with basic info.

        Returns a list of dicts: {Domain, Expires, IsOurDNS}
        """
        root = self._request("namecheap.domains.getList", {"PageSize": "100", "ListType": "ALL", "SortBy": "NAME"})
        result: List[Dict[str, str]] = []
        for d in root.findall(".//DomainGetListResult/Domain"):
            result.append(
                {
                    "Domain": d.attrib.get("Name", ""),
                    "Expires": d.attrib.get("Expires", ""),
                    "IsOurDNS": (d.attrib.get("IsOurDNS", "false").lower() == "true"),
                }
            )
        return result

    def get_hosts(self, domain: str) -> List[Dict[str, str]]:
        """Return DNS hosts for a domain.

        Returns list of dicts: {HostName, RecordType, Address, TTL, MXPref}
        """
        sld, tld = self._split_domain(domain)
        root = self._request(
            "namecheap.domains.dns.getHosts",
            {"SLD": sld, "TLD": tld},
        )
        hosts: List[Dict[str, str]] = []
        for h in root.findall(".//DomainDNSGetHostsResult/host"):
            hosts.append(
                {
                    "HostName": h.attrib.get("Name", ""),
                    "RecordType": h.attrib.get("Type", ""),
                    "Address": h.attrib.get("Address", ""),
                    "TTL": h.attrib.get("TTL", ""),
                    "MXPref": h.attrib.get("MXPref", ""),
                }
            )
        return hosts

    def set_hosts(self, domain: str, hosts: List[Dict[str, str]]) -> bool:
        """Set all hosts for the domain with provided list.

        hosts: list of dicts with keys HostName, RecordType, Address, TTL, MXPref (optional)
        """
        sld, tld = self._split_domain(domain)
        params: Dict[str, str] = {"SLD": sld, "TLD": tld}
        for idx, h in enumerate(hosts, start=1):
            params[f"HostName{idx}"] = h.get("HostName", "")
            params[f"RecordType{idx}"] = h.get("RecordType", "")
            params[f"Address{idx}"] = h.get("Address", "")
            if h.get("MXPref"):
                params[f"MXPref{idx}"] = str(h.get("MXPref"))
            if h.get("TTL"):
                params[f"TTL{idx}"] = str(h.get("TTL"))

        self._request("namecheap.domains.dns.setHosts", params)
        return True

    def add_or_update_record(
        self,
        domain: str,
        host: str,
        rtype: str,
        value: str,
        ttl: int = 1800,
        mx_pref: Optional[int] = None,
    ) -> Tuple[bool, List[Dict[str, str]]]:
        """Add or update a single record by merging with current hosts.

        Returns (changed: bool, new_hosts: list)
        """
        current = self.get_hosts(domain)

        normalized_host = host if host != "@" else "@"
        changed = False
        new_hosts: List[Dict[str, str]] = []
        updated = False

        for h in current:
            if h.get("HostName") == normalized_host and h.get("RecordType", "").upper() == rtype.upper():
                # Update existing
                if (
                    str(h.get("Address", "")) != str(value)
                    or str(h.get("TTL", "")) != str(ttl)
                    or (mx_pref is not None and str(h.get("MXPref", "")) != str(mx_pref))
                ):
                    changed = True
                new_hosts.append(
                    {
                        "HostName": normalized_host,
                        "RecordType": rtype.upper(),
                        "Address": value,
                        "TTL": str(ttl),
                        "MXPref": str(mx_pref) if mx_pref is not None else "",
                    }
                )
                updated = True
            else:
                new_hosts.append(h)

        if not updated:
            changed = True
            new_hosts.append(
                {
                    "HostName": normalized_host,
                    "RecordType": rtype.upper(),
                    "Address": value,
                    "TTL": str(ttl),
                    "MXPref": str(mx_pref) if mx_pref is not None else "",
                }
            )

        if changed:
            self.set_hosts(domain, new_hosts)
        return changed, new_hosts

    def add_or_update_txt(self, domain: str, host: str, value: str, ttl: int = 300) -> Tuple[bool, List[Dict[str, str]]]:
        return self.add_or_update_record(domain, host, "TXT", value, ttl)

    @staticmethod
    def _split_domain(domain: str) -> Tuple[str, str]:
        parts = domain.split(".")
        if len(parts) < 2:
            raise NamecheapAPIError(f"Invalid domain: {domain}")
        return parts[0], ".".join(parts[1:])
