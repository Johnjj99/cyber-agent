# scanners/web_scanner.py
import requests
import ssl
import socket
import re
from typing import Dict, List, Any
from pathlib import Path

# ---- Wordlist ----
def load_wordlist(filepath: str = "data/wordlists/common_dirs.txt") -> List[str]:
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        # Fallback default list
        return ["admin", "login", "panel", "api", "backup", "robots.txt", "sitemap.xml", ".git", "config", "test"]

# ---- Security Headers ----
def check_security_headers(host: str) -> List[Dict]:
    """Check for security headers and return list of errors."""
    errors = []
    try:
        resp = requests.get(f"https://{host}", timeout=5)
        headers = resp.headers
        if 'strict-transport-security' not in headers:
            errors.append({
                "field_path": "hsts",
                "error_type": "MISSING_HEADER",
                "message": "HSTS header missing"
            })
        if 'content-security-policy' not in headers:
            errors.append({
                "field_path": "csp",
                "error_type": "MISSING_HEADER",
                "message": "CSP header missing"
            })
        if 'x-frame-options' not in headers:
            errors.append({
                "field_path": "xfo",
                "error_type": "MISSING_HEADER",
                "message": "X-Frame-Options header missing"
            })
        if 'x-content-type-options' not in headers:
            errors.append({
                "field_path": "xcto",
                "error_type": "MISSING_HEADER",
                "message": "X-Content-Type-Options header missing"
            })
        if 'referrer-policy' not in headers:
            errors.append({
                "field_path": "rp",
                "error_type": "MISSING_HEADER",
                "message": "Referrer-Policy header missing"
            })
    except:
        errors.append({
            "field_path": "http",
            "error_type": "CONNECTION_ERROR",
            "message": "Failed to fetch HTTPS headers"
        })
    return errors

# ---- SSL/TLS ----
def check_ssl(host: str) -> List[Dict]:
    """Check SSL certificate validity."""
    errors = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # Optionally check expiry, but we'll just mark as valid if connection succeeds
                # If we wanted to check expiry, we'd parse cert['notAfter']
                # For now, we consider it valid if we can connect.
    except:
        errors.append({
            "field_path": "ssl",
            "error_type": "SSL_ERROR",
            "message": "SSL certificate invalid or connection failed"
        })
    return errors

# ---- SQL Injection ----
def check_sql_injection(host: str, params: Dict[str, str]) -> List[Dict]:
    """Test parameters for SQL injection vulnerabilities."""
    if not params:
        return []
    errors = []
    payloads = ["'", "' OR 1=1 --", "' UNION SELECT NULL--", "'; DROP TABLE users--"]
    for param, value in params.items():
        for payload in payloads:
            test_params = params.copy()
            test_params[param] = value + payload
            try:
                resp = requests.get(f"https://{host}", params=test_params, timeout=5)
                indicators = ["SQL syntax", "mysql", "ORA-", "PostgreSQL", "Unclosed quotation mark"]
                for indicator in indicators:
                    if indicator in resp.text:
                        errors.append({
                            "field_path": f"sqli_{param}",
                            "error_type": "SQL_INJECTION",
                            "message": f"Parameter '{param}' vulnerable to SQL injection"
                        })
                        break
            except:
                pass
    return errors

# ---- Directory Discovery with Wordlist ----
def check_directories_with_wordlist(host: str, wordlist: List[str] = None) -> List[Dict]:
    """Check for exposed directories using a wordlist."""
    if wordlist is None:
        wordlist = load_wordlist()
    errors = []
    for d in wordlist:
        try:
            resp = requests.get(f"https://{host}/{d}", timeout=3)
            if resp.status_code < 400:
                errors.append({
                    "field_path": f"dir_{d}",
                    "error_type": "DIRECTORY_EXPOSED",
                    "message": f"Directory '{d}' exposed (status {resp.status_code})"
                })
        except:
            pass
    return errors

# ---- Legacy directory check (kept for compatibility) ----
def check_directory_listing(host: str, wordlist: List[str] = None) -> List[str]:
    """Legacy function – returns list of exposed directory names."""
    if wordlist is None:
        wordlist = load_wordlist()
    found = []
    for d in wordlist:
        try:
            resp = requests.get(f"https://{host}/{d}", timeout=3)
            if resp.status_code < 400:
                found.append(d)
        except:
            pass
    return found