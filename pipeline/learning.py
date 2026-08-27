# pipeline/learning.py
import json
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class LearningStore:
    def __init__(self, storage_path="output/learning_store.json"):
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        # Always load (or create) the data
        self._data = self._load()

    def _load(self):
        """Load the store from disk, or create a default."""
        if not self.storage_path.exists():
            return {"failures": []}

        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if "failures" not in data or not isinstance(data["failures"], list):
                data["failures"] = []
            return data
        except Exception as e:
            logger.warning(f"Could not load learning store: {e}")
            return {"failures": []}

    def _save(self):
        """Write the current data to disk."""
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)

    def failure_exists(self, error_type, source_file=None, record_index=None,
                       field_name=None, error_category=None, resolved=None) -> bool:
        """
        Check if a failure with the same key fields already exists.
        """
        # Guard against missing _data (should not happen, but safety)
        if not hasattr(self, "_data") or self._data is None:
            self._data = {"failures": []}

        for f in self._data.get("failures", []):
            if (f.get("error_type") == error_type and
                f.get("source_file") == source_file and
                f.get("record_index") == record_index and
                f.get("field_name") == field_name and
                f.get("error_category") == error_category and
                f.get("resolved") == resolved):
                return True
        return False

    def record_failure(
        self,
        error_type,
        error_detail,
        source_file=None,
        record_index=None,
        field_name=None,
        error_category=None,
        fix_attempted=False,
        fix_applied=False,
        resolved=False,
        details=None,
        check_duplicate=True,
    ):
        """
        Record a failure. If check_duplicate is True, skip if a similar failure
        (same source, record, field, type, category, resolved status) already exists.
        """
        if check_duplicate:
            if self.failure_exists(
                error_type, source_file, record_index,
                field_name, error_category, resolved
            ):
                logger.debug(f"Skipping duplicate failure: {error_type} on record {record_index}")
                return

        failure = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "error_type": error_type,
            "error_detail": error_detail,
            "source_file": source_file,
            "record_index": record_index,
            "field_name": field_name,
            "error_category": error_category or error_type,
            "fix_attempted": bool(fix_attempted),
            "fix_applied": bool(fix_applied),
            "resolved": bool(resolved),
            "details": details or {},
        }

        self._data["failures"].append(failure)
        self._save()
        logger.info(
            f"Recorded failure: {error_type} "
            f"(field={field_name}, record={record_index}, resolved={resolved})"
        )

    def get_failures(self):
        """Return the list of all failures."""
        return self._data.get("failures", [])

    def clear(self):
        """Clear all failures."""
        self._data = {"failures": []}
        self._save()
        logger.info("LearningStore cleared")