#!/usr/bin/env python3
import random
import threading
from queue import Queue, Empty

import requests

from config.var import var


admin_path = [
    "admin/", "administrator/", "wp-admin/", "login/", "controlpanel/",
    "cpanel/", "adminpanel/", "manage/", "webadmin/", "admin_login/"
]


def scan_admin_paths(target, proxy=None, verbose=False):
    """Scan admin paths on the target."""
    log_file = var.log
    proxies = {"http": proxy, "https": proxy} if proxy else None
    queue = Queue()
    threads = []

    print(f"[+] Scanning admin paths on {target}")
    with open(log_file, "a") as filelog:
        filelog.write(f"\n[+] Scanning admin paths on {target}\n")

    def worker():
        # FIX: headers dibuat per-worker agar tidak ada shared mutable state
        # dan User-Agent dirotasi per request (lebih realistis)
        while True:
            try:
                path = queue.get(timeout=1)
            except Empty:
                break

            url = f"http://{target}/{path}"
            # FIX: sebelumnya `headers` global + random.choice dipanggil di luar loop
            # sehingga semua worker pakai UA yang sama. Sekarang dirotasi per request.
            headers = {"User-Agent": random.choice(var.ouruseragent)}

            if verbose:
                print(f"[-] Checking path: {url}")

            try:
                response = requests.get(
                    url, proxies=proxies, headers=headers,
                    timeout=10, verify=False, allow_redirects=False
                )
                status_line = f"{response.status_code} {response.reason}"

                # FIX: Hanya laporkan path yang "menarik" (200/301/302/401/403)
                # agar output tidak banjir 404.
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
                queue.task_done()

    for path in admin_path:
        queue.put(path)

    # FIX: thread count tidak melebihi jumlah task
    thread_count = min(10, len(admin_path))
    for _ in range(thread_count):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"[+] Admin path scan finished for {target}")