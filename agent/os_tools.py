# agent/os_tools.py
import os
import subprocess
import shutil
from pathlib import Path
from typing import List, Optional, Dict, Any

# Whitelist of allowed shell commands (prefixes)
ALLOWED_COMMANDS = (
    "ls", "pwd", "cat", "head", "tail", "echo", "mkdir", "rmdir", "cp", "mv",
    "python", "pip", "grep", "find", "wc", "sort", "uniq"
)

def list_directory(path: str = ".") -> List[str]:
    """List files and directories in the given path."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Path not found: {p}")
    return [str(x) for x in p.iterdir()]

def read_file(path: str) -> str:
    """Read a text file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")
    with open(p, "r", encoding="utf-8") as f:
        return f.read()

def write_file(path: str, content: str) -> None:
    """Write content to a file (overwrites)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)

def append_to_file(path: str, content: str) -> None:
    """Append content to a file."""
    p = Path(path)
    with open(p, "a", encoding="utf-8") as f:
        f.write(content)

def backup_file(path: str) -> str:
    """Create a .bak backup of the file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")
    backup = p.with_suffix(p.suffix + ".bak")
    shutil.copy2(p, backup)
    return str(backup)

def restore_backup(path: str) -> None:
    """Restore the .bak file (if exists)."""
    p = Path(path)
    backup = p.with_suffix(p.suffix + ".bak")
    if backup.exists():
        shutil.copy2(backup, p)

def run_shell_command(cmd: str, timeout: int = 30) -> Dict[str, Any]:
    """
    Run a shell command. Only allowed if cmd starts with one of ALLOWED_COMMANDS.
    Returns dict with 'stdout', 'stderr', 'returncode'.
    """
    # Security: check if command starts with an allowed prefix
    parts = cmd.strip().split()
    if not parts:
        raise ValueError("Empty command")
    if parts[0] not in ALLOWED_COMMANDS:
        raise PermissionError(f"Command '{parts[0]}' not allowed. Allowed: {ALLOWED_COMMANDS}")

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout", "returncode": -1}

def find_files(pattern: str, root: str = ".") -> List[str]:
    """Find files matching a glob pattern (e.g., '*.py')."""
    p = Path(root)
    return [str(x) for x in p.glob(pattern)]

def file_exists(path: str) -> bool:
    return Path(path).exists()