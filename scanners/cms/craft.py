# scanners/cms/craft.py
import re
import requests
from typing import List, Dict

def detect_craft_version(host: str) -> str:
    # Try meta tag
    try:
        resp = requests.get(f"https://{host}", timeout=3)
        if resp.status_code == 200:
            match = re.search(r'<meta name="generator" content="Craft CMS ([\d.]+)"', resp.text, re.IGNORECASE)
            if match:
                return match.group(1)
    except:
        pass
    return "unknown"

def check_admin_exposure(host: str) -> bool:
    for path in ["/admin", "/cp", "/backend", "/dashboard"]:
        try:
            resp = requests.get(f"https://{host}{path}", timeout=3)
            if resp.status_code < 400:
                return True
        except:
            pass
    return False

def check_debug_mode(host: str) -> bool:
    try:
        resp = requests.get(f"https://{host}/config/general.php", timeout=3)
        if resp.status_code == 200 and "dev" in resp.text:
            return True
    except:
        pass
    # Check for debug bar
    try:
        resp = requests.get(f"https://{host}", timeout=3)
        if "debug bar" in resp.text.lower() or "yii" in resp.text:
            return True
    except:
        pass
    return False

def check_config_exposure(host: str) -> bool:
    try:
        resp = requests.get(f"https://{host}/.env", timeout=3)
        if resp.status_code == 200:
            return True
    except:
        pass
    return False

def detect_plugins(host: str) -> List[str]:
    common = ["commerce", "contact-form", "seo", "redactor", "image-resizer"]
    found = []
    for plugin in common:
        try:
            resp = requests.get(f"https://{host}/craft/plugins/{plugin}/", timeout=3)
            if resp.status_code < 400:
                found.append(plugin)
        except:
            pass
    return found

def scan(host: str) -> List[Dict]:
    errors = []
    version = detect_craft_version(host)
    if version == "unknown":
        # Check if it's Craft by looking for common patterns
        try:
            resp = requests.get(f"https://{host}", timeout=3)
            if "craft" in resp.text.lower() or "csrf" in resp.text.lower():
                errors.append({
                    "field_path": "craft_detected",
                    "error_type": "INFO",
                    "message": "Craft CMS detected but version could not be determined"
                })
        except:
            pass
    else:
        errors.append({
            "field_path": "craft_version",
            "error_type": "INFO",
            "message": f"Craft CMS version {version} detected"
        })

    if check_admin_exposure(host):
        errors.append({
            "field_path": "craft_admin_exposed",
            "error_type": "ADMIN_EXPOSED",
            "message": "Craft CMS admin panel (/admin, /cp, etc.) is publicly accessible"
        })

    if check_debug_mode(host):
        errors.append({
            "field_path": "craft_debug_enabled",
            "error_type": "DEBUG_MODE",
            "message": "Craft CMS debug mode appears to be enabled"
        })

    if check_config_exposure(host):
        errors.append({
            "field_path": "craft_config_exposed",
            "error_type": "CONFIG_EXPOSED",
            "message": "Craft CMS configuration file (.env) is publicly accessible"
        })

    plugins = detect_plugins(host)
    for plugin in plugins:
        errors.append({
            "field_path": f"craft_plugin_{plugin}",
            "error_type": "PLUGIN_DETECTED",
            "message": f"Craft CMS plugin '{plugin}' detected"
        })

    return errors