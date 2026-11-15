#!/usr/bin/env python3
"""Structured logging untuk Darkjumper (console + file JSON)."""
import json
import logging
import os
import sys
from datetime import datetime

from config.var import var


class JsonFormatter(logging.Formatter):
    """Format log sebagai JSON per baris."""
    def format(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False)


def get_logger(name="darkjumper"):
    """Return logger terstruktur (console + file)."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG if getattr(var, "verbose", False) else logging.INFO)

    # Console handler (warna sederhana)
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if getattr(var, "verbose", False) else logging.INFO)
    console_fmt = logging.Formatter("[%(levelname)s] %(message)s")
    console.setFormatter(console_fmt)
    logger.addHandler(console)

    # File handler (JSON lines)
    log_file = getattr(var, "log", "logs/darkjumper.log")
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    file_handler = logging.FileHandler(log_file.replace(".log", ".jsonl"), encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(JsonFormatter())
    logger.addHandler(file_handler)

    return logger
