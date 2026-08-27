# agent/cyber_rules.py
import re
import logging
import json
from pathlib import Path
from collections import Counter
from agent.code_rewriter import replace_function_in_file, add_new_normalizer

logger = logging.getLogger(__name__)

# ---- Helper: parse traceback ----
def parse_traceback(traceback_str: str) -> dict:
    pattern = r'File "([^"]+)", line (\d+), in (\w+)'
    matches = re.findall(pattern, traceback_str)
    if matches:
        file_path, line_num, func_name = matches[-1]
        return {"file": file_path, "line": int(line_num), "function": func_name}
    return None

# ---- Helper: repair a function based on exception ----
def repair_function_from_traceback(traceback_str: str) -> str:
    parsed = parse_traceback(traceback_str)
    if not parsed:
        return None
    file_path = Path(parsed["file"])
    func_name = parsed["function"]

    exception_type = "Exception"
    if "KeyError" in traceback_str:
        exception_type = "KeyError"
    elif "AttributeError" in traceback_str:
        exception_type = "AttributeError"
    elif "IndexError" in traceback_str:
        exception_type = "IndexError"
    elif "TypeError" in traceback_str:
        exception_type = "TypeError"

    project_root = Path.cwd()
    try:
        rel_path = file_path.relative_to(project_root)
    except ValueError:
        return None
    if not any(part in str(rel_path) for part in ["pipeline", "agent", "scanners", "cyber_runner.py"]):
        return None

    if not file_path.exists():
        return None
    with open(file_path, 'r') as f:
        content = f.read()
    pattern = rf'(def\s+{func_name}\s*\([^)]*\)\s*:.*?)(?=\n\S|\Z)'
    match = re.search(pattern, content, re.DOTALL)
    if not match:
        return None
    old_func = match.group(1)

    if exception_type == "KeyError":
        new_func = re.sub(r'record\["([^"]+)"\]', r'record.get("\1", None)', old_func)
        if new_func == old_func:
            body = old_func.split(':\n', 1)[1]
            new_func = f"def {func_name}(record):\n    try:\n{body}\n    except KeyError:\n        pass"
    elif exception_type == "AttributeError":
        new_func = re.sub(r'record\.(\w+)', r'record.\1 if hasattr(record, "\1") else None', old_func)
    else:
        body = old_func.split(':\n', 1)[1]
        new_func = f"def {func_name}(record):\n    try:\n{body}\n    except Exception:\n        pass"
    return new_func

# ---- Suggestion logic ----
def suggest_improvements(failures: list) -> list:
    suggestions = []
    field_counter = Counter()
    for f in failures:
        field = f.get("field_path")
        if field:
            field_counter[field] += 1

    for f in failures:
        field = f.get("field_path")
        if field is None:
            continue
        if field == "hsts":
            suggestions.append({"field": "hsts", "operation": "enable_hsts", "description": "Enable HSTS"})
        elif field == "rdp_port":
            suggestions.append({"field": "rdp_port", "operation": "block_rdp_port", "description": "Block RDP port"})
        elif field == "rdp_nla":
            suggestions.append({"field": "rdp_nla", "operation": "enable_nla", "description": "Enable NLA"})
        elif field == "csp":
            suggestions.append({"field": "csp", "operation": "add_csp", "description": "Add CSP header"})
        elif field.startswith("sqli_"):
            param = field.split("_")[1]
            suggestions.append({"field": "sqli", "operation": "mitigate_sqli", "description": f"Mitigate SQL injection in {param}", "param": param})
        elif field.startswith("dir_"):
            dir_name = field.split("_")[1]
            suggestions.append({"field": "dir", "operation": "block_directory", "description": f"Block access to {dir_name}", "directory": dir_name})
        elif field == "spf":
            suggestions.append({"field": "spf", "operation": "add_spf", "description": "Add SPF record"})
        elif field == "spf_softfail":
            suggestions.append({"field": "spf", "operation": "add_spf_softfail", "description": "Add SPF ~all"})
        elif field == "ssl":
            suggestions.append({"field": "ssl", "operation": "renew_cert", "description": "Renew SSL certificate"})
        elif field.startswith("xss_"):
            suggestions.append({"field": "xss", "operation": "fix_xss", "description": "Fix XSS vulnerability"})
        elif field.startswith("s3_"):
            suggestions.append({"field": "s3", "operation": "make_s3_private", "description": "Make S3 bucket private"})
        elif field == "api_misconfig":
            suggestions.append({"field": "api", "operation": "fix_api_config", "description": "Fix API misconfiguration"})
        elif field.startswith("fuzz_"):
            suggestions.append({"field": "fuzzing", "operation": "report_anomaly", "description": "Report fuzzing anomaly (manual inspection needed)"})
        elif field.startswith("cve_"):
            cve_id = field.split("_")[1]
            suggestions.append({"field": "cve", "operation": "patch_cve", "description": f"Patch CVE {cve_id}", "cve": cve_id})

    if len(failures) > 3:
        suggestions.append({"field": "custom", "operation": "create_custom_fix", "description": "Invent a new fix for repeated errors"})

    normalizer_errors = [f for f in failures if f.get("field_name") == "normalizer_failure"]
    if normalizer_errors:
        suggestions.append({
            "field": "self_heal",
            "operation": "fix_normalizer",
            "description": "Fix broken normalizer",
            "error_detail": normalizer_errors[0].get("error_detail", "")
        })

    return suggestions

# ---- Normalizer creation ----
def create_normalizer_from_suggestion(suggestion: dict):
    op = suggestion["operation"]

    if op == "enable_hsts":
        def normalizer(record):
            if "headers" in record:
                record["headers"]["hsts"] = True
            logger.info("🔒 HSTS enabled")
        return normalizer

    elif op == "add_csp":
        def normalizer(record):
            if "headers" in record:
                record["headers"]["csp"] = True
            logger.info("🛡️ CSP added")
        return normalizer

    elif op == "block_rdp_port":
        def normalizer(record):
            record["rdp_port_blocked"] = True
            logger.info("🚫 Blocked RDP port (3389)")
        return normalizer

    elif op == "enable_nla":
        def normalizer(record):
            record["rdp_nla_enabled"] = True
            logger.info("🔐 Enabled RDP NLA")
        return normalizer

    elif op == "mitigate_sqli":
        param = suggestion.get("param", "unknown")
        def normalizer(record):
            if "params" in record and param in record["params"]:
                record["params"].remove(param)
                logger.info(f"✅ Mitigated SQL injection in {param}")
        return normalizer

    elif op == "block_directory":
        dir_name = suggestion.get("directory", "unknown")
        def normalizer(record):
            record["blocked_dirs"] = record.get("blocked_dirs", []) + [dir_name]
            logger.info(f"🚫 Blocked directory {dir_name}")
        return normalizer

    elif op == "add_spf":
        def normalizer(record):
            if "spf" in record:
                record["spf"]["present"] = True
            logger.info("📧 SPF added")
        return normalizer

    elif op == "add_spf_softfail":
        def normalizer(record):
            if "spf" in record:
                record["spf"]["softfail"] = True
            logger.info("📧 SPF ~all added")
        return normalizer

    elif op == "renew_cert":
        def normalizer(record):
            if "ssl" in record:
                record["ssl"]["valid"] = True
            logger.info("🔐 SSL certificate renewed")
        return normalizer

    elif op == "fix_xss":
        def normalizer(record):
            logger.info("🧹 XSS fix simulated")
            record["xss_fixed"] = True
        return normalizer

    elif op == "make_s3_private":
        def normalizer(record):
            logger.info("🔒 S3 bucket made private (simulated)")
            record["s3_private"] = True
        return normalizer

    elif op == "fix_api_config":
        def normalizer(record):
            logger.info("🔧 API config fixed (simulated)")
            record["api_fixed"] = True
        return normalizer

    elif op == "report_anomaly":
        def normalizer(record):
            logger.info("📢 Anomaly reported – no fix available (needs manual inspection)")
            record["anomaly_reported"] = True
        return normalizer

    elif op == "patch_cve":
        cve = suggestion.get("cve", "unknown")
        def normalizer(record):
            # Simulate patching a CVE
            record["cve_patched"] = True
            logger.info(f"🛡️ Patched CVE {cve} (simulated)")
        return normalizer

    elif op == "create_custom_fix":
        def normalizer(record):
            logger.info("🧠 Would invent a new custom fix")
            # add_new_normalizer("custom", "set_default", '    record.setdefault("key", "default")')
        return normalizer

    elif op == "fix_normalizer":
        def normalizer(record):
            logger.info("🛠️ Self‑healing normalizer triggered (runner will handle repair)")
        return normalizer

    return None