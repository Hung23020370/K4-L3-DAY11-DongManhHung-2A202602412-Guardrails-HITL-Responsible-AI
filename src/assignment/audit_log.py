"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        # Lưu thông tin request đang xử lý: {key: {"start_time": float, "input_text": str, "timestamp": str}}
        self._open: dict[str, dict] = {}

    def _get_tracking_key(self, user_id: str, request_id: str | None = None) -> str:
        """Tạo key định danh duy nhất cho từng phiên gọi request."""
        return request_id if request_id is not None else user_id

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id/user_id."""
        key = self._get_tracking_key(user_id, request_id)
        self._open[key] = {
            "start_time": time.time(),
            "timestamp": utc_now_iso(),
            "input_text": text,
            "user_id": user_id,
            "request_id": request_id,
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs."""
        key = self._get_tracking_key(user_id, request_id)
        start_info = self._open.pop(key, None)

        now = time.time()
        start_time = start_info["start_time"] if start_info else now
        latency_ms = round((now - start_time) * 1000, 2)
        input_text = start_info["input_text"] if start_info else ""
        timestamp = start_info["timestamp"] if start_info else utc_now_iso()

        log_entry = {
            "timestamp": timestamp,
            "request_id": request_id,
            "user_id": user_id,
            "input": input_text,
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": latency_ms,
        }
        self.logs.append(log_entry)

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        target_path = Path(filepath or default_audit_log_path())
        target_path.parent.mkdir(parents=True, exist_ok=True)

        with target_path.open("w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2, ensure_ascii=False)