# pipeline/cyber_validator.py
import logging
import json
import traceback
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from pipeline.learning import LearningStore
from scanners.web_scanner import *
from scanners.dns_scanner import *
from scanners.network.rdp import scan as rdp_scan
from scanners.parameter_discovery import discover_parameters
from scanners.web.xss import scan as xss_scan
from scanners.cloud.s3 import scan as s3_scan
from scanners.container.docker import scan as docker_scan
from scanners.api.rest import scan as api_scan
from scanners.cve_scanner import scan as cve_scan
from scanners.fuzzer import scan as fuzz_scan
from reporting.generator import generate_report, save_report
from scanners.api.advanced import scan as api_advanced_scan
from scanners.network.vpn import scan as vpn_scan
from scanners.cms.wordpress import scan as wp_scan
from scanners.cms.craft import scan as craft_scan
from scanners.cms.ghost import scan as ghost_scan
from scanners.cms.detector import detect_cms
from scanners.cms.fuzzer import scan as cms_fuzz_scan

logger = logging.getLogger(__name__)

EXPECTED_CHECKS = 20
NORMALIZERS = []
RULES = []
store = LearningStore()
CONFIG_PATH = Path("validator_config.json")
TARGETS_FILE = Path("targets.txt")

def load_targets():
    if TARGETS_FILE.exists():
        with open(TARGETS_FILE) as f:
            return [line.strip() for line in f if line.strip()]
    return ["example.com"]

def load_checks():
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return json.load(f).get("checks", [])
    return []

def register_normalizer(func):
    NORMALIZERS.append(func)

def clear_normalizers():
    NORMALIZERS.clear()

def apply_normalizers(record):
    for norm in NORMALIZERS:
        try:
            norm(record)
        except Exception as e:
            store.record_failure(
                error_type="NORMALIZER_ERROR",
                error_detail=str(e),
                source_file="cyber_validator",
                record_index=0,
                field_name="normalizer_failure",
                error_category="EXECUTION_ERROR",
                fix_attempted=False,
                fix_applied=False,
                resolved=False,
                details={
                    "traceback": traceback.format_exc(),
                    "operation": getattr(norm, "__name__", "unknown"),
                    "field": record.get("current_field", "unknown")
                },
                check_duplicate=True
            )

def scan_target(target):
    """Run all scanners on a single target and return errors."""
    errors = []
    # Web
    errors.extend(check_security_headers(target))
    errors.extend(check_ssl(target))
    errors.extend(check_directories_with_wordlist(target))
    # API Advanced
    errors.extend(api_advanced_scan(target))
    # VPN
    errors.extend(vpn_scan(target))
    # CMS static scans
    errors.extend(wp_scan(target))
    errors.extend(craft_scan(target))
    errors.extend(ghost_scan(target))

    # ---- CMS detection & fuzzing ----
    cms_type = detect_cms(target)
    if cms_type:
        errors.extend(cms_fuzz_scan(target, cms_type))

    # ---- Fetch main page for CVE scanning ----
    try:
        resp = requests.get(f"https://{target}", timeout=5)
        headers = resp.headers
        body = resp.text
        errors.extend(cve_scan(headers, body))
    except Exception as e:
        logger.debug(f"Failed to fetch {target} for CVE scan: {e}")

    # Parameters and XSS
    params = discover_parameters(target)
    flat_params = []
    for param_list in params.values():
        flat_params.extend(param_list)
    flat_params = list(set(flat_params))
    # XSS
    param_dict = {p: "" for p in flat_params}
    errors.extend(xss_scan(target, param_dict))
    # Fuzzing (anomaly detection)
    errors.extend(fuzz_scan(target, flat_params))
    # Cloud S3
    errors.extend(s3_scan(target))
    # Container Docker
    errors.extend(docker_scan())
    # API Security
    errors.extend(api_scan(target))
    # DNS
    errors.extend(check_spf(target))
    errors.extend(check_dkim(target))
    errors.extend(check_dmarc(target))
    errors.extend(check_dnssec(target))
    errors.extend(check_caa(target))
    # RDP
    errors.extend(rdp_scan(target))
    return errors

def validate_record(record):
    apply_normalizers(record)
    targets = load_targets()
    all_errors = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_target = {executor.submit(scan_target, t): t for t in targets}
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                errors = future.result()
                all_errors.extend(errors)
            except Exception as e:
                logger.error(f"Scan failed for {target}: {e}")

    record["errors"] = all_errors
    coverage = max(0, EXPECTED_CHECKS - len(all_errors))
    report = generate_report(targets, all_errors, coverage)
    save_report(report)

    if all_errors:
        for err in all_errors:
            store.record_failure(
                error_type=err.get("error_type", "VALUE_ERROR"),
                error_detail=err.get("message", ""),
                source_file="cyber_audit",
                record_index=0,
                field_name=err.get("field_path"),
                error_category=err.get("error_type"),
                fix_attempted=False,
                fix_applied=False,
                resolved=False,
                details=record,
                check_duplicate=True
            )

    return len(all_errors) == 0, all_errors
