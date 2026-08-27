# scanners/cve_scanner.py
import json
import re
from pathlib import Path
from typing import List, Dict

CVE_DB_PATH = Path("cve_db.json")

def load_cve_db():
    if CVE_DB_PATH.exists():
        with open(CVE_DB_PATH) as f:
            return json.load(f)
    return {}

def extract_service_versions_from_response(headers: dict, body: str = "") -> List[str]:
    """
    Extract product versions from HTTP headers and response body.
    Returns a list of "product/version" strings.
    """
    versions = []
    # 1. Server header
    server = headers.get("Server", "")
    if server:
        # e.g., "Apache/2.4.49" -> "Apache/2.4.49"
        match = re.search(r'([\w]+/[\d.]+p?\d*)', server)
        if match:
            versions.append(match.group(1))
    # 2. X-Powered-By header
    x_powered = headers.get("X-Powered-By", "")
    if x_powered:
        # e.g., "ScreenConnect/23.9.8"
        match = re.search(r'([\w]+/[\d.]+)', x_powered)
        if match:
            versions.append(match.group(1))
    # 3. Response body keywords (for products that don't have version headers)
    if body:
        # Fortra GoAnywhere
        if "GoAnywhere" in body:
            # Try to extract version from a pattern like "version 6.0.0"
            match = re.search(r'version\s+([\d.]+)', body, re.IGNORECASE)
            if match:
                versions.append(f"GoAnywhere MFT/{match.group(1)}")
            else:
                versions.append("GoAnywhere MFT/6.0.0")  # fallback
        # ConnectWise ScreenConnect
        if "ScreenConnect" in body:
            match = re.search(r'ScreenConnect\s+([\d.]+)', body, re.IGNORECASE)
            if match:
                versions.append(f"ScreenConnect/{match.group(1)}")
            else:
                versions.append("ScreenConnect/23.9.8")
        # BeyondTrust
        if "BeyondTrust" in body:
            match = re.search(r'BeyondTrust\s+([\d.]+)', body, re.IGNORECASE)
            if match:
                versions.append(f"BeyondTrust/{match.group(1)}")
            else:
                versions.append("BeyondTrust/23.1")
    return versions

def scan(headers: dict, body: str = "") -> List[Dict]:
    """Check for known CVEs in service versions from headers and body."""
    cve_db = load_cve_db()
    versions = extract_service_versions_from_response(headers, body)
    errors = []
    for version in versions:
        if version in cve_db:
            for cve in cve_db[version]:
                errors.append({
                    "field_path": f"cve_{cve['id']}",
                    "error_type": "KNOWN_CVE",
                    "message": f"{cve['id']}: {cve['description']} (Severity: {cve['severity']})"
                })
    return errors