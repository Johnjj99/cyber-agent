# agent/advanced_repair.py
import logging
import re
from collections import Counter
from pathlib import Path
from agent.code_rewriter import replace_function_in_file

logger = logging.getLogger(__name__)

def analyse_failures(failures: list) -> dict:
    """Analyse normalizer failures and detect patterns."""
    patterns = {}
    for f in failures:
        op = f.get("details", {}).get("operation")
        field = f.get("details", {}).get("field")
        error_type = f.get("error_type", "UNKNOWN")
        if op:
            key = (op, error_type, field)
            patterns[key] = patterns.get(key, 0) + 1
    return patterns

def generate_patch(op: str, error_type: str, field: str) -> str:
    """Generate a corrected version of the normalizer function."""
    file_path = Path("agent/cyber_rules.py")
    if not file_path.exists():
        return None
    with open(file_path, 'r') as f:
        content = f.read()
    # Find the function definition for this operation (we assume it's named like normalize_*_op)
    # First, try to find a function that contains the operation name.
    pattern = rf'def\s+(\w+)\s*\([^)]*\)\s*:.*?(\n\s*return|\n\s*logger\.info|\n\s*record|$)'
    matches = re.finditer(pattern, content, re.DOTALL)
    func_name = None
    func_code = None
    for match in matches:
        full_def = match.group(0)
        if op in full_def:
            func_name = match.group(1)
            func_code = full_def
            break
    if not func_code:
        return None
    # Generate a fix based on error type
    if error_type == "KeyError" and field:
        # Add .get() fallback for the specific field
        new_func = re.sub(rf'record\["{field}"\]', f'record.get("{field}", None)', func_code)
        if new_func == func_code:
            # If no direct access, wrap in try/except
            body = func_code.split(':\n', 1)[1]
            new_func = f"def {func_name}(record):\n    try:\n{body}\n    except KeyError:\n        pass"
        return new_func
    # Other patterns can be added later (e.g., AttributeError, IndexError)
    return None

def apply_advanced_repair(failures: list) -> bool:
    """Analyse failures and apply a targeted patch."""
    patterns = analyse_failures(failures)
    for (op, error_type, field), count in patterns.items():
        if count >= 3:  # threshold
            logger.info(f"🛠️ Advanced repair: {op} fails {count} times with {error_type} on {field}")
            new_code = generate_patch(op, error_type, field)
            if new_code:
                file_path = Path("agent/cyber_rules.py")
                # Extract function name from new_code
                import re
                func_match = re.search(r'def\s+(\w+)', new_code)
                if func_match:
                    func_name = func_match.group(1)
                    success = replace_function_in_file(file_path, func_name, new_code)
                    if success:
                        logger.info(f"✅ Advanced repair applied to {func_name}")
                        return True
    return False