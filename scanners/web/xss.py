# scanners/web/xss.py
import requests
from typing import List, Dict

PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><img onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "'><script>alert(1)</script>",
]

def scan(host: str, params: Dict[str, str]) -> List[Dict]:
    """Test for reflected XSS vulnerabilities."""
    if not params:
        return []
    vulnerable = []
    for param, value in params.items():
        for payload in PAYLOADS:
            test_params = params.copy()
            test_params[param] = value + payload
            try:
                resp = requests.get(f"https://{host}", params=test_params, timeout=5)
                if payload in resp.text and not is_escaped(payload, resp.text):
                    vulnerable.append({
                        "field_path": f"xss_{param}",
                        "error_type": "XSS_VULNERABILITY",
                        "message": f"Parameter '{param}' is vulnerable to XSS (payload: {payload})"
                    })
                    break
            except:
                pass
    return vulnerable

def is_escaped(payload: str, text: str) -> bool:
    escaped_variants = [
        payload.replace("<", "&lt;").replace(">", "&gt;"),
        payload.replace('"', "&quot;"),
        payload.replace("'", "&#39;"),
    ]
    for variant in escaped_variants:
        if variant in text:
            return True
    return False
