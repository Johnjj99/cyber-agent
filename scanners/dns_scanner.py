# scanners/dns_scanner.py
import dns.resolver
from typing import List, Dict

def check_spf(domain: str) -> List[Dict]:
    errors = []
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_present = False
        softfail = False
        for txt in answers:
            if 'v=spf1' in txt.to_text():
                spf_present = True
                softfail = "~all" in txt.to_text() or "-all" in txt.to_text()
                break
        if not spf_present:
            errors.append({
                "field_path": "spf",
                "error_type": "MISSING_DNS",
                "message": "SPF record missing"
            })
        if spf_present and not softfail:
            errors.append({
                "field_path": "spf_softfail",
                "error_type": "WEAK_SPF",
                "message": "SPF missing ~all or -all"
            })
    except:
        # If DNS resolution fails, treat as missing
        errors.append({
            "field_path": "spf",
            "error_type": "MISSING_DNS",
            "message": "SPF record missing (DNS resolution failed)"
        })
    return errors

def check_dkim(domain: str) -> List[Dict]:
    selectors = ['default', 'google', 'mail', 'dkim', 'selector1', 'selector2']
    for sel in selectors:
        try:
            dns.resolver.resolve(f'{sel}._domainkey.{domain}', 'TXT')
            return []  # DKIM present – no error
        except:
            continue
    return [{
        "field_path": "dkim",
        "error_type": "MISSING_DNS",
        "message": "DKIM record missing"
    }]

def check_dmarc(domain: str) -> List[Dict]:
    errors = []
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        present = False
        policy = None
        for txt in answers:
            if 'v=DMARC1' in txt.to_text():
                present = True
                if 'p=reject' in txt.to_text():
                    policy = 'reject'
                elif 'p=quarantine' in txt.to_text():
                    policy = 'quarantine'
                break
        if not present:
            errors.append({
                "field_path": "dmarc",
                "error_type": "MISSING_DNS",
                "message": "DMARC record missing"
            })
        elif policy not in ['reject', 'quarantine']:
            errors.append({
                "field_path": "dmarc_policy",
                "error_type": "WEAK_DMARC",
                "message": f"DMARC policy is {policy or 'none'} – should be quarantine or reject"
            })
    except:
        errors.append({
            "field_path": "dmarc",
            "error_type": "MISSING_DNS",
            "message": "DMARC record missing (DNS resolution failed)"
        })
    return errors

def check_dnssec(domain: str) -> List[Dict]:
    try:
        dns.resolver.resolve(domain, 'DNSKEY')
        return []  # DNSSEC enabled
    except:
        return [{
            "field_path": "dnssec",
            "error_type": "MISSING_DNSSEC",
            "message": "DNSSEC not enabled"
        }]

def check_caa(domain: str) -> List[Dict]:
    try:
        dns.resolver.resolve(domain, 'CAA')
        return []  # CAA present
    except:
        return [{
            "field_path": "caa",
            "error_type": "MISSING_CAA",
            "message": "CAA record missing"
        }]