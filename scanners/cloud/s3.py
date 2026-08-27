# scanners/cloud/s3.py
import requests
import re
from typing import List, Dict

def scan(domain: str) -> List[Dict]:
    """Check if domain has a publicly accessible S3 bucket."""
    # Generate candidate bucket names
    candidates = [
        domain,
        domain.replace('.', '-'),
        domain.split('.')[0],
        f"{domain.split('.')[0]}-bucket",
        f"{domain}-static",
        f"{domain}-media",
        f"{domain.split('.')[0]}-files",
    ]
    errors = []
    for bucket in candidates:
        url = f"https://{bucket}.s3.amazonaws.com/"
        try:
            resp = requests.head(url, timeout=3)
            if resp.status_code == 200:
                errors.append({
                    "field_path": f"s3_{bucket}",
                    "error_type": "PUBLIC_S3_BUCKET",
                    "message": f"Public S3 bucket found: {bucket}"
                })
                break
        except:
            pass
    return errors
