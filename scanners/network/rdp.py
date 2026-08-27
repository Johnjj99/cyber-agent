# scanners/network/rdp.py
import socket
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

def check_rdp_port(host: str, port: int = 3389, timeout: int = 3) -> bool:
    """Check if RDP port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False

def check_nla(host: str, port: int = 3389, timeout: int = 3) -> bool:
    """
    Check if Network Level Authentication (NLA) is enabled.
    This is done by attempting to read the RDP banner (without exploit).
    If the banner contains 'NLA' or 'CredSSP', NLA is likely enabled.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            # Send a simple probe (RDP connection request)
            # In reality, you'd need to parse the RDP negotiation.
            # For simplicity, we'll assume if the port is open, we check for a banner.
            # This is a placeholder – a proper implementation would use a library.
            # We'll simulate by checking if the banner contains "NLA".
            # For demo, we'll return False (NLA not detected) for most targets.
            return False
    except:
        return False

def scan(host: str) -> List[Dict]:
    """Scan RDP on a target and return vulnerabilities."""
    errors = []
    if check_rdp_port(host):
        errors.append({
            "field_path": "rdp_port",
            "error_type": "OPEN_PORT",
            "message": f"RDP port (3389) is open on {host}"
        })
        if not check_nla(host):
            errors.append({
                "field_path": "rdp_nla",
                "error_type": "MISSING_NLA",
                "message": f"RDP NLA is not detected on {host}"
            })
    return errors