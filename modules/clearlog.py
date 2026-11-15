#!/usr/bin/env python3
import os
from config import var

def clear_logs():
    """Clear log files and temporary files."""
    log_file = var.log
    files = [log_file, "data/reverse.txt", "data/subpage.txt"]
    try:
        for file in files:
            if os.path.exists(file):
                os.remove(file)
                print(f"[+] Cleared file: {file}")
    except OSError as e:
        print(f"[!] Error clearing logs: {e}")
