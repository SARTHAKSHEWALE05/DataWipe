#!/usr/bin/env python3
"""
logger_module.py
Phase 4: Logging & Reporting for secure wiping
"""

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

LOG_FILE = Path("wipe_log.json")

def compute_hash(text: str) -> str:
    """Generate SHA-256 hash for integrity verification."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def log_wipe(device: dict, result: str, dry_run: bool = True):
    """Append a wipe attempt to log file."""
    entry = {
        "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "device": {
            "path": device.get("path"),
            "model": device.get("model") or device.get("name"),
            "serial": device.get("serial"),
            "size": device.get("size"),
            "type": device.get("detected_type"),
        },
        "dry_run": dry_run,
        "result": result.strip(),
    }
    entry["entry_hash"] = compute_hash(json.dumps(entry, sort_keys=True))

    # Append to log file
    log = []
    if LOG_FILE.exists():
        try:
            log = json.loads(LOG_FILE.read_text())
        except Exception:
            log = []
    log.append(entry)
    LOG_FILE.write_text(json.dumps(log, indent=2))

    return entry

def load_logs():
    """Load all previous logs."""
    if LOG_FILE.exists():
        try:
            return json.loads(LOG_FILE.read_text())
        except Exception:
            return []
    return []

def attach_certificate_to_entry(entry_hash: str, cert_meta: dict):
    """
    Find the log entry with entry_hash and attach certificate metadata into it.
    Returns True if updated, False otherwise.
    """
    if not LOG_FILE.exists():
        return False
    try:
        log = json.loads(LOG_FILE.read_text())
    except Exception:
        return False

    updated = False
    for e in log:
        if e.get("entry_hash") == entry_hash:
            e.setdefault("certificate", {})
            # copy only essential metadata
            e["certificate"].update({
                "cert_id": cert_meta.get("cert_id"),
                "cert_hash": cert_meta.get("cert_hash"),
                "json_path": cert_meta.get("json_path"),
                "pdf_path": cert_meta.get("pdf_path"),
                "qr_path": cert_meta.get("qr_path"),
                "generated_at": cert_meta.get("generated_at")
            })
            e["cert_hash"] = cert_meta.get("cert_hash")
            updated = True
            break

    if updated:
        LOG_FILE.write_text(json.dumps(log, indent=2))
    return updated
