"""
Assignment 11 — Monitoring & Alerting starter.

Tracks metrics and triggers alerts when thresholds are exceeded.
Never blocks by itself — helps operations respond to incidents.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_metrics_path() -> str:
    """Always resolve to <repo>/outputs/metrics.json."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "metrics.json")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class MonitoringAlert:
    """Collects security metrics and evaluates alerting rules."""

    def __init__(self, block_rate_threshold: float = 0.5):
        self.name = "monitoring_alert"
        self.block_rate_threshold = block_rate_threshold
        self.metrics = {
            "total_requests": 0,
            "blocked_requests": 0,
            "rate_limited_count": 0,
            "last_updated": utc_now_iso(),
        }
        self.alerts: list[dict] = []

    def record_metrics(
        self,
        total_requests: int = 0,
        blocked_requests: int = 0,
        rate_limited_count: int = 0,
    ):
        """Record or increment metric counters."""
        self.metrics["total_requests"] += total_requests
        self.metrics["blocked_requests"] += blocked_requests
        self.metrics["rate_limited_count"] += rate_limited_count
        self.metrics["last_updated"] = utc_now_iso()
        self.check_metrics()

    def check_metrics(self) -> list[dict]:
        """Check if metrics exceed thresholds and create alerts."""
        total = self.metrics["total_requests"]
        blocked = self.metrics["blocked_requests"]
        self.alerts.clear()

        if total > 0:
            block_rate = blocked / total
            if block_rate >= self.block_rate_threshold:
                self.alerts.append({
                    "timestamp": utc_now_iso(),
                    "level": "WARNING",
                    "type": "HIGH_BLOCK_RATE",
                    "message": f"Block rate at {block_rate:.1%} exceeds threshold of {self.block_rate_threshold:.1%}",
                })

        if self.metrics["rate_limited_count"] > 0:
            self.alerts.append({
                "timestamp": utc_now_iso(),
                "level": "INFO",
                "type": "RATE_LIMIT_TRIGGERED",
                "message": f"Rate limit was triggered {self.metrics['rate_limited_count']} times",
            })

        return self.alerts

    def export_json(self, filepath: str | None = None):
        """Export metrics and alerts to outputs/metrics.json."""
        target_path = Path(filepath or default_metrics_path())
        target_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "metrics": self.metrics,
            "alerts": self.alerts if self.alerts else self.check_metrics(),
            "status": "HEALTHY" if not any(a.get("level") == "CRITICAL" for a in self.alerts) else "ALERTING",
        }

        with target_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)