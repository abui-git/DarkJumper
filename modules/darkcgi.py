#!/usr/bin/env python3
import random
import threading
from queue import Queue, Empty

import requests

from config.var import var


def scan_cgi(target, proxy=None, verbose=False):
    """Scan CGI paths on the target."""
    log_file = var.log
    cgi_list = var.cgilist
    proxies = {"http": proxy, "https": proxy} if proxy else None
    queue = Queue()
    threads = []

    try:
        with open(cgi_list, "r", encoding="utf-8", errors="ignore") as f:
            cgi_paths = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Error: CGI list not found at {cgi_list}")
        return

    if not cgi_paths:
        print("[!] CGI list is empty")
        return

    # FIX: deduplikasi path
    cgi_paths = list(dict.fromkeys(cgi_paths))

    print(f"[+] Scanning {len(cgi_paths)} CGI paths on {target}")
    with open(log_file, "a") as filelog:
        filelog.write(f"\n[+] Scanning CGI paths on {target}\n")

    def worker():
        while True:
            # FIX: hindari race queue.empty() vs get()
            try:
                path = queue.get(timeout=1)
            except Empty:
                break

            try:
                url = f"http://{target}/{path}"
                # FIX: headers per-request (rotasi UA)
                headers = {"User-Agent": random.choice(var.ouruseragent)}

                if verbose:
                    print(f"[-] Checking path: {url}")

                try:
                    response = requests.get(
                        url, proxies=proxies, headers=headers,
                        timeout=10, verify=False, allow_redirects=False
                    )
                    status_line = f"{response.status_code} {response.reason}"

                    # FIX: hanya laporkan path "menarik" agar log tidak banjir 404
                    if response.status_code in (200, 301, 302, 401, 403):
                        print(f"[!] Found: {url} -> {status_line}")
                        with open(log_file, "a") as filelog:
                            filelog.write(f"[!] Found: {url} -> {status_line}\n")
                    elif verbose:
                        print(f"[-] {url} -> {status_line}")
                        with open(log_file, "a") as filelog:
                            filelog.write(f"[-] {url} -> {status_line}\n")

                except requests.RequestException as e:
                    print(f"[!] Error checking {url}: {e}")

            finally:
                # FIX: task_done dijamin dipanggil
                queue.task_done()

    for path in cgi_paths:
        queue.put(path)

    # FIX: thread_count tidak melebihi jumlah task, minimal 1
    thread_count = min(10, len(cgi_paths))
    for _ in range(thread_count):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"[+] CGI scan finished for {target}")