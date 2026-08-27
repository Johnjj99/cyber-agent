# scanners/cms/detector.py
import re
import requests
from typing import Optional

def detect_cms(host: str) -> Optional[str]:
    try:
        resp = requests.get(f"https://{host}", timeout=3)
        if resp.status_code != 200:
            return None
        text = resp.text
        # WordPress
        if "wp-content" in text or "wp-includes" in text or "WordPress" in text:
            return "wordpress"
        # Craft
        if "craft" in text.lower() or "Craft CMS" in text:
            return "craft"
        # Ghost
        if "ghost" in text.lower() or "casper" in text.lower():
            return "ghost"
    except:
        pass
    return None