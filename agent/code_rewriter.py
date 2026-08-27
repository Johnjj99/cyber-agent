# agent/code_rewriter.py
import ast
import shutil
import logging
import importlib
import re
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

# ---- Configuration ----
DYNAMIC_NORMALIZERS_PATH = Path("pipeline/dynamic_normalizers.py")
TEST_FILE_PATH = Path("tests/test_suite.py")
BACKUP_DIR = Path("backups")

# ---- Helpers ----
def safe_identifier(name: str) -> str:
    """Sanitise a string to be a valid Python identifier."""
    return re.sub(r'[^a-zA-Z0-9_]', '_', name)

# ---- Backup & Rollback ----
def backup_file(file_path: Path) -> Path:
    """Create a timestamped backup of a file."""
    if not file_path.exists():
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.touch()
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / f"{file_path.stem}_{timestamp}{file_path.suffix}"
    shutil.copy2(file_path, backup_path)
    logger.info(f"📦 Backup created: {backup_path}")
    return backup_path

def rollback(backup_path: Path, target_path: Path) -> bool:
    if backup_path and backup_path.exists():
        shutil.copy2(backup_path, target_path)
        logger.info(f"↩️ Rolled back to {backup_path}")
        return True
    return False

# ---- Syntax validation ----
def validate_syntax(code: str) -> bool:
    try:
        ast.parse(code)
        return True
    except SyntaxError as e:
        logger.error(f"❌ Syntax error: {e}")
        return False

# ---- File operations ----
def append_code_to_file(file_path: Path, code: str, register_line: str = "") -> bool:
    """Append code to a file with backup, rollback on failure."""
    if not validate_syntax(code):
        return False
    backup = backup_file(file_path)
    try:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(f"\n\n{code}\n")
            if register_line:
                f.write(f"{register_line}\n")
        logger.info(f"✅ Appended code to {file_path}")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to write: {e}")
        if backup:
            rollback(backup, file_path)
        return False

def replace_function_in_file(file_path: Path, func_name: str, new_func_code: str) -> bool:
    """Replace a function definition in a Python file using regex."""
    if not file_path.exists():
        logger.error(f"File {file_path} does not exist")
        return False
    if not validate_syntax(new_func_code):
        return False

    backup = backup_file(file_path)
    try:
        with open(file_path, "r") as f:
            content = f.read()
        pattern = rf'(def\s+{func_name}\s*\([^)]*\)\s*:.*?)(?=\n\S|\Z)'
        new_content = re.sub(pattern, new_func_code, content, flags=re.DOTALL)
        if new_content == content:
            logger.warning(f"Function {func_name} not found in {file_path}")
            return False
        with open(file_path, "w") as f:
            f.write(new_content)
        logger.info(f"✅ Replaced function {func_name} in {file_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to replace function: {e}")
        if backup:
            rollback(backup, file_path)
        return False

# ---- Test generation ----
def generate_normalizer_function(field: str, operation: str, code_body: str) -> tuple[str, str]:
    """Build a complete function definition."""
    safe_field = safe_identifier(field)
    safe_op = safe_identifier(operation)
    func_name = f"normalize_{safe_field}_{safe_op}".replace("-", "_")
    func_code = f"""
def {func_name}(record: dict) -> None:
    \"\"\"Auto-generated normalizer for {field} ({operation}).\"\"\"
{code_body}
"""
    return func_name, func_code

def add_new_normalizer(field: str, operation: str, code_body: str) -> bool:
    """Generate, validate, backup, and append a new normalizer."""
    func_name, func_code = generate_normalizer_function(field, operation, code_body)
    return append_code_to_file(
        DYNAMIC_NORMALIZERS_PATH,
        func_code,
        register_line=f"register_normalizer({func_name})"
    )

def append_test_function(test_code: str) -> bool:
    """Append a new test function to the test suite."""
    return append_code_to_file(TEST_FILE_PATH, test_code)

# ---- Reload dynamic normalizers ----
def reload_dynamic_normalizers():
    """Reload the dynamic_normalizers module to make new functions available."""
    try:
        import pipeline.dynamic_normalizers
        importlib.reload(pipeline.dynamic_normalizers)
        from pipeline.dynamic_normalizers import NORMALIZERS
        from pipeline.test_validator import register_normalizer
        for norm in NORMALIZERS:
            register_normalizer(norm)
        logger.info(f"🔄 Reloaded {len(NORMALIZERS)} dynamic normalizers")
    except Exception as e:
        logger.warning(f"Could not reload dynamic normalizers: {e}")