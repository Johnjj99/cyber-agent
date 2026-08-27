# scanners/fuzzer.py
import requests
import time
import statistics
from typing import List, Dict

# ---- Payloads ----
PAYLOADS = [
    # SQL Injection
    "'", '"', "' OR 1=1 --", '" OR 1=1 --',
    "' UNION SELECT NULL--", '; DROP TABLE users--',
    # Path Traversal
    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    # NoSQL
    "{'$gt': ''}", "{'$ne': null}",
    # LDAP Injection
    "*", ")(&)",
    # XSS
    "<script>alert(1)</script>",
    "\"><img onerror=alert(1)>",
    # Server-Side Template Injection (SSTI)
    "{{7*7}}", "${7*7}",
    # Command Injection
    "; id", "| whoami", "&& whoami",
    # Format Strings
    "%s", "%x", "%n",
    # Null Byte
    "\x00",
]

def fuzz_parameter(host: str, param: str, base_value: str = "test") -> List[Dict]:
    """Fuzz a single parameter with anomaly detection."""
    anomalies = []
    base_url = f"https://{host}"

    # ---- Baseline (3 requests for statistics) ----
    base_statuses = []
    base_lengths = []
    base_times = []
    for _ in range(3):
        try:
            resp = requests.get(base_url, params={param: base_value}, timeout=3)
            base_statuses.append(resp.status_code)
            base_lengths.append(len(resp.text))
            base_times.append(resp.elapsed.total_seconds())
        except:
            return anomalies

    if not base_lengths:
        return anomalies

    # Statistics
    avg_len = statistics.mean(base_lengths)
    std_len = statistics.stdev(base_lengths) if len(base_lengths) > 1 else 10
    avg_time = statistics.mean(base_times) if base_times else 0
    std_time = statistics.stdev(base_times) if len(base_times) > 1 else 0.1

    # ---- Fuzz ----
    for payload in PAYLOADS:
        test_params = {param: base_value + payload}
        try:
            start = time.time()
            resp = requests.get(base_url, params=test_params, timeout=3)
            elapsed = time.time() - start

            # Status code change
            if resp.status_code not in base_statuses:
                anomalies.append({
                    "field_path": f"fuzz_{param}",
                    "error_type": "FUZZING_ANOMALY",
                    "message": f"Parameter '{param}' with payload '{payload}' changed status code to {resp.status_code}"
                })
            # Length anomaly (> 3 std devs)
            elif abs(len(resp.text) - avg_len) > 3 * std_len:
                anomalies.append({
                    "field_path": f"fuzz_{param}",
                    "error_type": "FUZZING_ANOMALY",
                    "message": f"Parameter '{param}' with payload '{payload}' changed response length by {len(resp.text) - avg_len}"
                })
            # Time anomaly (> 3 std devs)
            elif elapsed > avg_time + 3 * std_time:
                anomalies.append({
                    "field_path": f"fuzz_{param}",
                    "error_type": "FUZZING_ANOMALY",
                    "message": f"Parameter '{param}' with payload '{payload}' slowed response to {elapsed:.2f}s (avg: {avg_time:.2f}s)"
                })
            # Error indicators
            for indicator in ["SQL syntax", "mysql", "ORA-", "Traceback", "Warning:", "Fatal error", "Unclosed quotation mark"]:
                if indicator in resp.text:
                    anomalies.append({
                        "field_path": f"fuzz_{param}",
                        "error_type": "FUZZING_ANOMALY",
                        "message": f"Parameter '{param}' with payload '{payload}' triggered error: {indicator}"
                    })
                    break
        except:
            pass

    return anomalies

def scan(host: str, params: List[str]) -> List[Dict]:
    """Run fuzzing on all parameters."""
    all_anomalies = []
    for param in params:
        anomalies = fuzz_parameter(host, param)
        all_anomalies.extend(anomalies)
    return all_anomalies