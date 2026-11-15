#!/usr/bin/env python3
"""Manajemen temuan: JSON, CSV, SARIF."""
import csv
import json
import os
import threading
from datetime import datetime

from config.var import var


_lock = threading.Lock()


class Findings:
    """Koleksi temuan dengan export JSON/CSV/SARIF."""

    def __init__(self):
        self.items = []

    def add(self, finding):
        """Tambah temuan (thread-safe)."""
        finding.setdefault("timestamp", datetime.utcnow().isoformat() + "Z")
        with _lock:
            self.items.append(finding)
            self._persist_json()

    def _persist_json(self):
        """Simpan ke JSON (append)."""
        output = getattr(var, "output_json", "reports/findings.json")
        os.makedirs(os.path.dirname(output), exist_ok=True)
        try:
            existing = []
            if os.path.exists(output):
                with open(output) as f:
                    existing = json.load(f)
            existing.append(self.items[-1])
            with open(output, "w") as f:
                json.dump(existing, f, indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, ValueError, OSError):
            pass

    def export_csv(self, path="reports/findings.csv"):
        """Export ke CSV."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not self.items:
            return
        keys = ["timestamp", "target", "type", "url", "payload", "severity"]
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(self.items)

    def export_sarif(self, path="reports/findings.sarif"):
        """Export ke SARIF (untuk integrasi CI/CD)."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "Darkjumper", "version": "5.7"}},
                "results": [
                    {
                        "ruleId": f"darkjumper.{item.get('type', 'unknown')}",
                        "level": "error" if item.get("severity") == "high" else "warning",
                        "message": {"text": f"{item.get('type')} at {item.get('url')}"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": item.get("url", "")}}}],
                    }
                    for item in self.items
                ],
            }],
        }
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(sarif, f, indent=2)

    def summary(self):
        """Ringkasan temuan per tipe."""
        summary = {}
        for item in self.items:
            t = item.get("type", "unknown")
            summary[t] = summary.get(t, 0) + 1
        return summary


# Singleton
findings = Findings()
