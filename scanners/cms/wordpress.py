# scanners/cms/wordpress.py
import re
import requests
from typing import List, Dict

# ---- Version detection ----
def detect_wordpress_version(host: str) -> str:
    try:
        resp = requests.get(f"https://{host}/readme.html", timeout=3)
        if resp.status_code == 200:
            match = re.search(r'WordPress (\d+\.\d+\.\d+)', resp.text)
            if match:
                return match.group(1)
    except:
        pass
    try:
        resp = requests.get(f"https://{host}", timeout=3)
        if resp.status_code == 200:
            match = re.search(r'<meta name="generator" content="WordPress ([\d.]+)"', resp.text, re.IGNORECASE)
            if match:
                return match.group(1)
    except:
        pass
    try:
        resp = requests.get(f"https://{host}/wp-includes/version.php", timeout=3)
        if resp.status_code == 200:
            match = re.search(r"\$wp_version = '([^']+)'", resp.text)
            if match:
                return match.group(1)
    except:
        pass
    return "unknown"

# ---- Admin panel exposure ----
def check_admin_exposure(host: str) -> bool:
    try:
        resp = requests.get(f"https://{host}/wp-admin", timeout=3)
        return resp.status_code < 400
    except:
        return False

# ---- Debug mode ----
def check_debug_mode(host: str) -> bool:
    try:
        resp = requests.get(f"https://{host}/wp-config.php", timeout=3)
        if resp.status_code == 200 and "define('WP_DEBUG'" in resp.text:
            return True
    except:
        pass
    try:
        resp = requests.get(f"https://{host}/?p=999999", timeout=3)
        if "Notice:" in resp.text or "Warning:" in resp.text:
            return True
    except:
        pass
    return False

# ---- Plugin enumeration ----
def enumerate_plugins(host: str) -> List[str]:
    common_plugins = [
        "akismet", "jetpack", "woocommerce", "elementor", "yoast", "contact-form-7",
        "wordfence", "wp-rocket", "all-in-one-wp-security", "wp-super-cache",
        "updraftplus", "classic-editor", "advanced-custom-fields", "w3-total-cache"
    ]
    found = []
    for plugin in common_plugins:
        try:
            resp = requests.get(f"https://{host}/wp-content/plugins/{plugin}/readme.txt", timeout=3)
            if resp.status_code == 200:
                found.append(plugin)
        except:
            pass
    return found

# ---- Theme detection ----
def detect_theme(host: str) -> str:
    try:
        resp = requests.get(f"https://{host}", timeout=3)
        if resp.status_code == 200:
            match = re.search(r'wp-content/themes/([^/]+)/', resp.text)
            if match:
                return match.group(1)
    except:
        pass
    return "unknown"

# ---- CVE lookup ----
def check_wordpress_cves(version: str) -> List[Dict]:
    cve_map = {
        "5.8.0": [{"id": "CVE-2021-42343", "severity": "High", "description": "XSS in WordPress 5.8.0"}],
        "5.7.0": [{"id": "CVE-2021-29447", "severity": "Critical", "description": "SQL injection in WordPress 5.7.0"}],
    }
    return cve_map.get(version, [])

# ---- Main scan ----
def scan(host: str) -> List[Dict]:
    errors = []
    version = detect_wordpress_version(host)
    if version != "unknown":
        cves = check_wordpress_cves(version)
        for cve in cves:
            errors.append({
                "field_path": f"cve_{cve['id']}",
                "error_type": "KNOWN_CVE",
                "message": f"{cve['id']}: {cve['description']} (Severity: {cve['severity']})"
            })
    else:
        errors.append({
            "field_path": "wordpress_version",
            "error_type": "INFO",
            "message": "WordPress detected but version could not be determined"
        })

    if check_admin_exposure(host):
        errors.append({
            "field_path": "wp_admin_exposed",
            "error_type": "ADMIN_EXPOSED",
            "message": "WordPress admin panel (/wp-admin) is publicly accessible"
        })

    if check_debug_mode(host):
        errors.append({
            "field_path": "wp_debug_enabled",
            "error_type": "DEBUG_MODE",
            "message": "WordPress debug mode (WP_DEBUG) appears to be enabled"
        })

    plugins = enumerate_plugins(host)
    for plugin in plugins:
        errors.append({
            "field_path": f"wp_plugin_{plugin}",
            "error_type": "PLUGIN_DETECTED",
            "message": f"WordPress plugin '{plugin}' detected – check for known vulnerabilities"
        })

    theme = detect_theme(host)
    if theme != "unknown":
        errors.append({
            "field_path": f"wp_theme_{theme}",
            "error_type": "THEME_DETECTED",
            "message": f"WordPress theme '{theme}' detected – check for known vulnerabilities"
        })

    return errors
