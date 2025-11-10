"""
Simple in-memory DNS operation log with capped history.
"""
from __future__ import annotations

import threading
import time
from typing import Dict, List

_MAX_LOGS = 500
_lock = threading.Lock()
_logs: List[Dict] = []

def add_log_entry(operation: str, domain: str = "", status: str = "info", message: str = "", target: str = "") -> None:
    """Add a DNS log entry to in-memory buffer.

    Parameters:
        operation: Operation name (e.g., getList, getHosts, setHosts, getToken, insert)
        domain: Domain involved in the operation
        status: success|error|info
        message: Short description
        target: Optional host/record target
    """
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "operation": operation,
        "domain": domain,
        "status": status,
        "message": message,
        "target": target,
    }
    with _lock:
        _logs.append(entry)
        if len(_logs) > _MAX_LOGS:
            del _logs[: len(_logs) - _MAX_LOGS]

def get_recent_logs(limit: int = 50) -> List[Dict]:
    """Return up to `limit` most recent log entries (oldest first)."""
    with _lock:
        return list(_logs[-limit:])
