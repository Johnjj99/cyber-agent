# scanners/cms/fuzzer.py
import requests
import re
from typing import List, Dict, Optional

# ---- Endpoint definitions per CMS ----
WP_ENDPOINTS = [
    ("/wp-admin/admin-ajax.php", "action", ["heartbeat", "query-attachments", "get-comments"]),
    ("/wp-json/wp/v2/posts", "id", ["1", "2", "3"]),
    ("/xmlrpc.php", "method", ["pingback.ping", "wp.getUsersBlogs"]),
    ("/wp-json/jetpack/v4/", "url", ["http://example.com"]),
]

CRAFT_ENDPOINTS = [
    ("/admin/actions", "action", ["login", "save", "delete"]),
    ("/api/v1/entries", "id", ["1", "2"]),
    ("/index.php", "p", ["admin/actions/login"]),
]

GHOST_ENDPOINTS = [
    ("/ghost/api/v3/admin/posts", "id", ["1", "2"]),
    ("/ghost/api/v3/admin/settings", "key", ["title", "description"]),
]

# ---- Payloads ----
PAYLOADS = [
    # SQL Injection
    "'", "' OR 1=1 --", "' UNION SELECT NULL--",
    # Path Traversal
    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    # XSS
    "<script>alert(1)</script>", "\"><img onerror=alert(1)>",
    # SSTI
    "{{7*7}}", "${7*7}",
    # Command Injection
    "; id", "| whoami",
    # Null Byte
    "\x00",
]

# ---- Main scan ----
def scan(host: str, cms_type: Optional[str] = None) -> List[Dict]:
    """
    Run CMS‑specific fuzzing on known endpoints.
    If cms_type is provided, only test that CMS; otherwise test all.
    """
    errors = []
    endpoints_to_test = []
    if cms_type == "wordpress":
        endpoints_to_test = WP_ENDPOINTS
    elif cms_type == "craft":
        endpoints_to_test = CRAFT_ENDPOINTS
    elif cms_type == "ghost":
        endpoints_to_test = GHOST_ENDPOINTS
    else:
        # If unknown, test all (safe fallback)
        endpoints_to_test = WP_ENDPOINTS + CRAFT_ENDPOINTS + GHOST_ENDPOINTS

    for endpoint, param, test_values in endpoints_to_test:
        for value in test_values:
            for payload in PAYLOADS:
                test_params = {param: value + payload}
                try:
                    resp = requests.get(f"https://{host}{endpoint}", params=test_params, timeout=3)
                    # Check for CMS‑specific error indicators
                    indicators = ["SQL syntax", "mysql", "ORA-", "Traceback", "Warning:", "Fatal error", "Unclosed quotation mark"]
                    for indicator in indicators:
                        if indicator in resp.text:
                            errors.append({
                                "field_path": f"cms_fuzz_{param}",
                                "error_type": "CMS_FUZZING_ANOMALY",
                                "message": f"CMS endpoint {endpoint} with parameter '{param}' triggered error: {indicator} (payload: {payload})"
                            })
                            break
                except:
                    pass
    return errors