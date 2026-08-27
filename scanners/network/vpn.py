# scanners/network/vpn.py
import socket
import requests
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

def check_port_udp(host: str, port: int, timeout: int = 3) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x00", (host, port))
        data, addr = sock.recvfrom(1024)
        sock.close()
        return True
    except:
        return False

def check_vpn_web(host: str, path: str) -> bool:
    try:
        resp = requests.get(f"https://{host}{path}", timeout=3)
        return resp.status_code < 400
    except:
        return False

def scan(host: str) -> List[Dict]:
    errors = []
    # OpenVPN (UDP 1194)
    if check_port_udp(host, 1194):
        errors.append({
            "field_path": "vpn_openvpn",
            "error_type": "VPN_DETECTED",
            "message": "OpenVPN service detected on UDP/1194"
        })
    # IPsec (UDP 500, 4500)
    if check_port_udp(host, 500) or check_port_udp(host, 4500):
        errors.append({
            "field_path": "vpn_ipsec",
            "error_type": "VPN_DETECTED",
            "message": "IPsec service detected (UDP/500 or 4500)"
        })
    # WireGuard (UDP 51820)
    if check_port_udp(host, 51820):
        errors.append({
            "field_path": "vpn_wireguard",
            "error_type": "VPN_DETECTED",
            "message": "WireGuard service detected on UDP/51820"
        })
    # SSL VPN (HTTPS)
    for path in ["/vpn", "/sra", "/sslvpn", "/remote", "/login"]:
        if check_vpn_web(host, path):
            errors.append({
                "field_path": f"vpn_ssl_{path.replace('/','')}",
                "error_type": "VPN_DETECTED",
                "message": f"SSL VPN endpoint found: {path}"
            })
            break
    return errors