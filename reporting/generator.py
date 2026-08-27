# reporting/generator.py
import json
import time
import logging
from pathlib import Path
from typing import List, Dict

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path("output")
REPORT_FILE = OUTPUT_DIR / "report.json"

def generate_report(targets: List[str], errors: List[Dict], fitness: float) -> Dict:
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "targets": targets,
        "fitness": round(fitness, 2),
        "total_vulnerabilities": len(errors),
        "vulnerabilities": []
    }
    for err in errors:
        report["vulnerabilities"].append({
            "field": err.get("field_path", "unknown"),
            "type": err.get("error_type", "UNKNOWN"),
            "description": err.get("message", ""),
            "severity": _infer_severity(err.get("error_type", ""))
        })
    return report

def _infer_severity(error_type: str) -> str:
    # High severity
    high = {
        "OPEN_PORT", "SQL_INJECTION", "MISSING_NLA", "DIRECTORY_EXPOSED",
        "XSS_VULNERABILITY", "PUBLIC_S3_BUCKET", "KNOWN_CVE", "FUZZING_ANOMALY",
        "VPN_DETECTED", "ADMIN_EXPOSED", "CONFIG_EXPOSED", "CMS_FUZZING_ANOMALY"
    }
    # Medium severity
    medium = {
        "MISSING_HEADER", "WEAK_SPF", "MISSING_DNS", "API_MISCONFIG",
        "JWT_WEAKNESS", "API_RATE_LIMIT", "DEBUG_MODE", "PLUGIN_DETECTED",
        "THEME_DETECTED"
    }
    # Info severity
    info = {"INFO", "WARNING"}

    if error_type in high:
        return "High"
    elif error_type in medium:
        return "Medium"
    elif error_type in info:
        return "Info"
    return "Info"

def save_report(report: Dict) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)
    logger.info(f"📄 Report saved to {REPORT_FILE}")
