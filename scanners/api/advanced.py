# scanners/api/advanced.py
import requests
import time
from typing import List, Dict

def check_rate_limiting(host: str, endpoint: str = "/api") -> List[Dict]:
    errors = []
    try:
        for i in range(5):
            resp = requests.get(f"https://{host}{endpoint}", timeout=3)
            if resp.status_code in [429, 503]:
                errors.append({
                    "field_path": "api_rate_limit",
                    "error_type": "API_MISCONFIG",
                    "message": "Rate limiting detected – endpoint may be vulnerable to DoS"
                })
                break
            time.sleep(0.1)
    except:
        pass
    return errors

def check_jwt_weakness(host: str, endpoint: str = "/api/auth") -> List[Dict]:
    errors = []
    # Try 'none' algorithm
    headers = {"Authorization": "Bearer none"}
    try:
        resp = requests.get(f"https://{host}{endpoint}", headers=headers, timeout=3)
        if resp.status_code < 400:
            errors.append({
                "field_path": "jwt_weakness",
                "error_type": "API_MISCONFIG",
                "message": "JWT authentication bypassed with 'none' algorithm"
            })
    except:
        pass
    # Try empty token
    headers = {"Authorization": "Bearer "}
    try:
        resp = requests.get(f"https://{host}{endpoint}", headers=headers, timeout=3)
        if resp.status_code < 400:
            errors.append({
                "field_path": "jwt_weakness",
                "error_type": "API_MISCONFIG",
                "message": "JWT authentication bypassed with empty token"
            })
    except:
        pass
    return errors

def scan(host: str) -> List[Dict]:
    errors = []
    errors.extend(check_rate_limiting(host))
    errors.extend(check_jwt_weakness(host))
    return errors