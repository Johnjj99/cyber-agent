# scanners/cms/ghost.py
import re
import requests
from typing import List, Dict

def detect_ghost_version(host: str) -> str:
    try:
        resp = requests.get(f"https://{host}", timeout=3)
        if resp.status_code == 200:
            # Look for meta tag
            match = re.search(r'<meta name="generator" content="Ghost ([\d.]+)"', resp.text, re.IGNORECASE)
            if match:
                return match.group(1)
            # Or API version
            match = re.search(r'"version":"([\d.]+)"', resp.text)
            if match:
                return match.group(1)
    except:
        pass
    return "unknown"

def check_admin_exposure(host: str) -> bool:
    try:
        resp = requests.get(f"https://{host}/ghost", timeout=3)
        return resp.status_code < 400
    except:
        return False

def check_debug_mode(host: str) -> bool:
    try:
        resp = requests.get(f"https://{host}/ghost/api/", timeout=3)
        # If API returns detailed error, debug is likely on
        if resp.status_code == 500 or "stack" in resp.text:
            return True
    except:
        pass
    return False

def check_config_exposure(host: str) -> bool:
    try:
        resp = requests.get(f"https://{host}/config.js", timeout=3)
        if resp.status_code == 200 and "ghost" in resp.text:
            return True
    except:
        pass
    return False

def scan(host: str) -> List[Dict]:
    errors = []
    version = detect_ghost_version(host)
    if version == "unknown":
        try:
            resp = requests.get(f"https://{host}", timeout=3)
            if "ghost" in resp.text.lower() or "casper" in resp.text.lower():
                errors.append({
                    "field_path": "ghost_detected",
                    "error_type": "INFO",
                    "message": "Ghost CMS detected but version could not be determined"
                })
        except:
            pass
    else:
        errors.append({
            "field_path": "ghost_version",
            "error_type": "INFO",
            "message": f"Ghost CMS version {version} detected"
        })

    if check_admin_exposure(host):
        errors.append({
            "field_path": "ghost_admin_exposed",
            "error_type": "ADMIN_EXPOSED",
            "message": "Ghost CMS admin panel (/ghost) is publicly accessible"
        })

    if check_debug_mode(host):
        errors.append({
            "field_path": "ghost_debug_enabled",
            "error_type": "DEBUG_MODE",
            "message": "Ghost CMS debug mode appears to be enabled"
        })

    if check_config_exposure(host):
        errors.append({
            "field_path": "ghost_config_exposed",
            "error_type": "CONFIG_EXPOSED",
            "message": "Ghost CMS configuration file (config.js) is publicly accessible"
        })

    return errors