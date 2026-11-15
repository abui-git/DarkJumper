#!/usr/bin/env python3
import argparse
import sys
import socket
import time
import requests
import threading
from queue import Queue, Empty
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import random
from core.scanner import Scanner
from modules import adminpath, darkcgi, devilzc0de, ftpbrute, subscan, daemoninfo
from config.var import var
import base64
import os
import re
import warnings

# Suppress SSL warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)


def print_banner():
    """Print the Darkjumper banner."""
    print(var.darkjumperface2)


def reverse_mode(target, proxy=None, verbose=False):
    """
    Reverse IP lookup menggunakan HackerTarget API (utama) dan
    RapidDNS (fallback) untuk menemukan domain lain di server yang sama.
    """
    log_file = var.log
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        ip = "Unknown"

    print(f"[+] Target hostname: {target}")
    print(f"[+] Target IP: {ip}")
    print(f"[+] Use proxy: {proxy}")
    print(f"[+] Verbosity: {verbose}")
    print(f"[+] Time Starting: {time.strftime('%X')}")
    print("[+] Trying reverse IP lookup...")

    with open(log_file, "a") as filelog:
        filelog.write(f"\n[+] Target set: {target}\n[+] Trying reverse IP lookup...\n")

    proxies = {"http": proxy, "https": proxy} if proxy else None
    domains = set()
    headers = {"User-Agent": random.choice(var.ouruseragent)}

    # ---------------- Sumber 1: HackerTarget (teks biasa) ----------------
    url = f"{var.machine}{target}"
    try:
        response = requests.get(
            url, proxies=proxies, headers=headers, timeout=20, verify=False
        )
        text = response.text.strip()
        error_markers = [
            "error", "API count exceeded", "no records found",
            "invalid", "blacklisted",
        ]
        if any(m.lower() in text.lower() for m in error_markers):
            print(f"[!] HackerTarget: {text[:200]}")
            with open(log_file, "a") as filelog:
                filelog.write(f"[!] HackerTarget: {text[:200]}\n")
        else:
            for line in text.splitlines():
                domain = line.strip()
                if not domain or "." not in domain:
                    continue
                if domain.lower().startswith(("error", "api", "no ")):
                    continue
                full_url = f"http://{domain}"
                if full_url in domains:
                    continue
                domains.add(full_url)
                print(full_url)
                with open(var.filerev, "a") as filerev:
                    filerev.write(f"{full_url}\n")
            if domains:
                print(f"[+] HackerTarget: {len(domains)} domain ditemukan")
    except requests.RequestException as e:
        print(f"[!] HackerTarget error: {e}")
        with open(log_file, "a") as filelog:
            filelog.write(f"[!] HackerTarget error: {e}\n")

    # ---------------- Sumber 2: RapidDNS fallback (scraping) ----------------
    if not domains and ip != "Unknown":
        print("[+] Fallback ke RapidDNS...")
        fallback_url = f"{var.machine_fallback}{ip}"
        try:
            response = requests.get(
                fallback_url, proxies=proxies, headers=headers,
                timeout=20, verify=False
            )
            soup = BeautifulSoup(response.text, "html.parser")
            for row in soup.select("table.table tbody tr"):
                cells = row.find_all("td")
                if len(cells) >= 1:
                    domain = cells[0].get_text(strip=True).lower()
                    if not domain or "." not in domain:
                        continue
                    full_url = f"http://{domain}"
                    if full_url in domains:
                        continue
                    domains.add(full_url)
                    print(full_url)
                    with open(var.filerev, "a") as filerev:
                        filerev.write(f"{full_url}\n")
            if domains:
                print(f"[+] RapidDNS: {len(domains)} domain ditemukan")
            else:
                print("[!] RapidDNS: tidak ada hasil (mungkin rate-limit atau IP tidak dipetakan)")
        except requests.RequestException as e:
            print(f"[!] RapidDNS error: {e}")

    print(f"[+] Found: {len(domains)} domains hosted at this IP")
    with open(log_file, "a") as filelog:
        filelog.write(f"[+] Found: {len(domains)} domains hosted at this IP\n")

    return list(domains)


def scan_vulnerabilities(target, mode, domains, proxy=None, verbose=False, session=None):
    """Scan vulnerabilities based on mode."""
    proxies = {"http": proxy, "https": proxy} if proxy else None
    queue = Queue()
    threads = []

    def worker():
        while not queue.empty():
            try:
                domain = queue.get(timeout=1)
            except Empty:
                break
            try:
                if mode in ["injection", "full"]:
                    print(f"[+] Injection scan mode applied to: {domain}")
                    devilzc0de.scan_vulnerabilities(
                        domain, types=["sqli", "blind"], proxy=proxy, verbose=verbose,
                        session=session
                    )
                    if var.subpages == "yes":
                        subscan.scan_subpages(domain, proxy=proxy, verbose=verbose, session=session)
                if mode in ["inclusion", "full"]:
                    print(f"[+] Inclusion scan mode applied to: {domain}")
                    devilzc0de.scan_vulnerabilities(
                        domain, types=["rfi", "lfi", "rce"], proxy=proxy, verbose=verbose, session=session
                    )
            finally:
                queue.task_done()

    if mode in ["injection", "inclusion", "full"]:
        for domain in domains:
            queue.put(domain)
        thread_count = min(10, max(1, len(domains)))
        for _ in range(thread_count):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

    if mode == "cgidirs":
        darkcgi.scan_cgi(target, proxy=proxy, verbose=verbose)
    if mode == "ftpanon":
        ftpbrute.check_anonymous(target, verbose=verbose)
    if mode == "scanadminpath":
        adminpath.scan_admin_paths(target, proxy=proxy, verbose=verbose)
    if mode == "daemoninfo":
        daemoninfo.scan_daemon(target, verbose=verbose)
    if mode == "headerinfo":
        try:
            response = requests.head(
                f"https://{target}", proxies=proxies,
                headers={"User-Agent": random.choice(var.ouruseragent)},
                timeout=10, verify=False
            )
            print(response.headers)
        except requests.RequestException:
            try:
                response = requests.head(
                    f"http://{target}", proxies=proxies,
                    headers={"User-Agent": random.choice(var.ouruseragent)},
                    timeout=10
                )
                print(response.headers)
            except requests.RequestException as e:
                print(f"[!] Error fetching headers: {e}")
    if mode == "checkip":
        check_ip(proxy=proxy)
    if mode == "converter":
        data = input("[-] Input data to encode: ")
        print(f"[+] Hex: {data.encode().hex()}")
        print(f"[+] Base64: {base64.b64encode(data.encode()).decode()}")
    if mode == "portscan":
        # FIX: Gunakan argumen CLI, bukan sys.argv langsung
        try:
            port_range = getattr(var, "port_range", None)
            if not port_range:
                port_range = input("[-] Enter port range (e.g., 1-1000): ")
            start_port, end_port = map(int, port_range.split("-"))
            port_scan(target, start_port, end_port, verbose=verbose)
        except (ValueError, AttributeError):
            print("[!] Port range format: start-end (e.g., 1-1000)")
    if mode == "enum":
        enum_scan(target, verbose=verbose)


def check_ip(proxy=None):
    """Check IP or proxy information."""
    url = "http://my-addr.com/your-ip-and-city-country-isp-latitude-longitude/geo-ip-region-lookup/my_geo.php"
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = {"User-Agent": random.choice(var.ouruseragent)}

    try:
        response = requests.get(url, proxies=proxies, headers=headers, timeout=10)
        patterns = {
            "IP": r"<b>IP</b></td><td class='td_val'>(.*?)</td></tr>",
            "Continent": r"<td class='td_var'>CONTINENT CODE</td>\n<td class='td_val'>(.*?)</td>",
            "Country Code": r"<td class='td_var'>COUNTRY CODE</td>\n<td class='td_val'>(.*?)</td>",
            "Region Name": r"<td class='td_var'>REGION NAME</td>\n<td class='td_val'>(.*?) <font color='red'><- it's your region</font></td>",
            "Region Code": r"<td class='td_var'>REGION CODE</td>\n<td class='td_val'>(.*?)</td>\n</tr>",
            "City": r"<td class='td_var'>CITY</td>\n<td class='td_val'>(.*?) <font color='red'><- it's your city</font></td>",
            "Latitude": r"<td class='td_var'>LATITUDE</td>\n<td class='td_val'>(.*?)</td>",
            "Longitude": r"<td class='td_var'>LONGITUDE</td>\n<td class='td_val'>(.*)</td>",
            "Provider": r"<td class='td_val'>(.*)<font color='red'><- it's your provider</font></td>",
        }
        results = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, response.text)
            results[key] = match.group(1) if match else "Unknown"
        for key, value in results.items():
            print(f"[+] Your {key}: {value}")
    except requests.RequestException as e:
        print(f"[!] Error checking IP: {e}")


def port_scan(target, start_port, end_port, verbose=False):
    """Scan open ports on target."""
    print(f"[+] Scanning open ports on {target} ({start_port}-{end_port})")
    queue = Queue()
    threads = []
    open_ports = []

    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"[!] Port {port} is open!")
                open_ports.append(port)
            elif verbose:
                print(f"[-] Port {port} is closed")
            sock.close()
        except socket.gaierror:
            print(f"[!] Error resolving {target}")
        except OSError:
            pass

    for port in range(start_port, end_port + 1):
        queue.put(port)

    def worker():
        while not queue.empty():
            try:
                port = queue.get(timeout=1)
            except Empty:
                break
            try:
                scan_port(port)
            finally:
                queue.task_done()

    thread_count = min(50, end_port - start_port + 1)
    for _ in range(thread_count):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"[+] Port scan complete. {len(open_ports)} open port(s) found.")


def enum_scan(target, verbose=False):
    """Enumerate possible users."""
    print("[+] Testing user enumeration")
    targa = f"http://{target}/~root"
    try:
        response = requests.get(
            targa,
            headers={"User-Agent": random.choice(var.ouruseragent)},
            timeout=10
        )
        if "Forbidden" in response.text:
            print("[!] Server has user enumeration vulnerability!")
            # FIX: Cek file exists sebelum dibaca
            if not os.path.exists(var.filerev):
                print(f"[!] File {var.filerev} not found. Run reverse mode first.")
                return
            with open(var.filerev, "r") as f:
                domains = [
                    line.strip().replace("http://", "").replace("https://", "")
                    .replace("www.", "").replace(".", "").replace("/", "")
                    for line in f if line.strip()
                ]
            for domain in domains:
                for length in range(4, min(9, len(domain) + 1)):
                    username = domain[:length]
                    if not username:
                        continue
                    url = f"http://{target}/~{username}"
                    try:
                        response = requests.get(
                            url,
                            headers={"User-Agent": random.choice(var.ouruseragent)},
                            timeout=10
                        )
                        if response.status_code in [200, 301]:
                            print(f"[!] W00t !!! Found possible user: {username}")
                            print(f"[!] Check this out: {url}")
                            with open(var.log, "a") as filelog:
                                filelog.write(
                                    f"\n[!] Found possible user: {username}\n"
                                    f"[!] Check this out: {url}\n"
                                )
                            if var.autobrute:
                                ftpbrute.brute_force(
                                    target, username, var.wordlist, verbose=verbose
                                )
                    except requests.RequestException:
                        continue
        else:
            print("[!] Server is configured well, user enumeration not possible.")
    except requests.RequestException as e:
        print(f"[!] Error checking {targa}: {e}")



def auto_login(login_url, username, password, proxy=None, verbose=False, security="low"):
    """
    Login otomatis ke aplikasi web (misal DVWA) dan kembalikan Session.
    Mendukung CSRF token (DVWA v1.10).
    """
    import re as _re
    from requests import Session

    proxies = {"http": proxy, "https": proxy} if proxy else None
    session = Session()
    headers = {"User-Agent": random.choice(var.ouruseragent)}

    try:
        # Ambil halaman login untuk CSRF token
        r = session.get(login_url, proxies=proxies, headers=headers, timeout=10, verify=False)
        token_match = _re.search(r"user_token['\"]?\s*value=['\"]([a-f0-9]+)", r.text)
        token = token_match.group(1) if token_match else None
        if verbose:
            print(f"[*] Login token: {token}")

        # Kirim login
        data = {"username": username, "password": password, "Login": "Login"}
        if token:
            data["user_token"] = token

        # Deteksi action form login
        action_match = _re.search(r'<form[^>]+action=["\']([^"\']+)', r.text)
        action = action_match.group(1) if action_match else login_url
        if not action.startswith("http"):
            from urllib.parse import urljoin
            action = urljoin(login_url, action)

        r = session.post(action, data=data, proxies=proxies, headers=headers,
                         timeout=10, verify=False, allow_redirects=True)

        # Cek login berhasil
        if "Login" in r.text and "logout" not in r.text.lower():
            print("[!] Login mungkin gagal — cek username/password")
        else:
            print(f"[+] Login berhasil: {username}")

        # Set security=low (khusus DVWA)
        from urllib.parse import urljoin
        sec_url = urljoin(login_url, "security.php")
        try:
            session.post(sec_url, data={"security": security, "seclev_submit": "Submit"},
                         proxies=proxies, headers=headers, timeout=10, verify=False)
            if verbose:
                print(f"[+] Security level diset ke {security}")
        except Exception:
            pass

        return session
    except Exception as e:
        print(f"[!] Auto-login gagal: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="Darkjumper v5.7 - Web Vulnerability Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target hostname or IP")
    parser.add_argument("-m", "--mode", required=True, choices=[
        "reverseonly", "injection", "inclusion", "full", "cgidirs", "enum", "portscan",
        "headerinfo", "scanadminpath", "daemoninfo", "converter", "checkip", "ftpanon"
    ], help="Scanning mode")
    parser.add_argument("-p", "--proxy", help="Proxy address (e.g., 127.0.0.1:8080)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    parser.add_argument("-a", "--autobrute", action="store_true", help="Auto-bruteforce after enumeration")
    parser.add_argument("-r", "--port-range", dest="port_range", default="1-1000",
                        help="Port range for portscan mode (default: 1-1000)")
    parser.add_argument("--no-reverse", dest="no_reverse", action="store_true",
                        help="Paksa scan tunggal (hanya target awal, tanpa reverse IP)")
    parser.add_argument("--reverse", dest="force_reverse", action="store_true",
                        help="Paksa reverse IP walau mode biasanya tidak reverse")
    parser.add_argument("--exploit",
                        choices=["detect", "dbs", "tables", "columns", "dump", "users", "passwords"],
                        default="detect",
                        help="Level eksploitasi sqlmap jika SQLi ditemukan (default: detect)")
    parser.add_argument("--i-have-permission", dest="i_have_permission",
                        action="store_true",
                        help="Konfirmasi izin untuk --exploit dump/users/passwords")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Jeda antar request dalam detik (rate limiting, default: 0)")
    parser.add_argument("--login-url", help="URL login untuk auto-login (misal DVWA)")
    parser.add_argument("--login-user", help="Username untuk auto-login")
    parser.add_argument("--login-pass", help="Password untuk auto-login")
    parser.add_argument("--security", default="low", choices=["low", "medium", "high"],
                        help="Security level untuk DVWA (default: low)")
    parser.add_argument("--ai-verify", dest="ai_verify", action="store_true",
                        help="Aktifkan verifikasi AI (filter false positive)")
    parser.add_argument("--ai-provider", default="deepseek",
                        choices=["deepseek", "groq", "openai", "ollama"],
                        help="Provider AI (default: deepseek)")
    parser.add_argument("--ai-model", help="Model AI")
    parser.add_argument("--ai-base-url", dest="ai_base_url",
                        help="Base URL untuk Ollama")
    args = parser.parse_args()

    var.proxy = args.proxy
    var.verbose = args.verbose
    var.autobrute = args.autobrute
    var.port_range = args.port_range
    var.no_reverse = args.no_reverse
    var.ai_verify = getattr(args, "ai_verify", False)
    var.ai_provider = getattr(args, "ai_provider", "deepseek")
    if getattr(args, "ai_model", None):
        var.ai_model = args.ai_model
    if getattr(args, "ai_base_url", None):
        var.ai_base_url = args.ai_base_url
    var.force_reverse = args.force_reverse
    var.exploit_level = args.exploit
    var.delay = args.delay
    var.login_url = args.login_url
    var.login_user = args.login_user
    var.login_pass = args.login_pass

    # Auto-login jika diminta
    session = None
    if args.login_url and args.login_user and args.login_pass:
        print(f"[*] Auto-login ke {args.login_url}")
        session = auto_login(
            args.login_url, args.login_user, args.login_pass,
            proxy=args.proxy, verbose=args.verbose, security=args.security
        )

    # Validasi: eksploitasi data butuh --i-have-permission
    if args.exploit in ["dump", "users", "passwords"] and not args.i_have_permission:
        print("[!] Eksploitasi data (dump/users/passwords) butuh --i-have-permission")
        print("[!] Pastikan kamu punya izin tertulis dari pemilik sistem")
        sys.exit(1)

    # FIX: Bersihkan protokol dari target dan validasi
    # Jangan lower() seluruh URL — hanya hostname yang case-insensitive
    target = args.target.strip()
    target = re.sub(r"^https?://", "", target)
    target = target.rstrip("/")
    # Lowercase hanya hostname (sebelum path pertama "/")
    if "/" in target:
        host, rest = target.split("/", 1)
        target = host.lower() + "/" + rest
    else:
        target = target.lower()
    if not target:
        print("[!] Invalid target")
        sys.exit(1)

    # Validasi target: resolusi DNS
    try:
        hostname = target.split("/")[0].split(":")[0]
        socket.gethostbyname(hostname)
    except socket.gaierror:
        print(f"[!] Target tidak bisa di-resolve: {hostname}")
        print("[!] Periksa koneksi internet atau ejaan hostname")
        sys.exit(1)

    print_banner()
    with open(var.log, "a") as filelog:
        filelog.write(f"\n[!] Starting Darkjumper at {time.strftime('%X')}\n")

    # --- Tentukan apakah perlu reverse ---
    reverse_modes = ["injection", "inclusion", "full", "enum"]
    need_reverse = False

    if args.no_reverse:
        # Paksa scan tunggal
        need_reverse = False
        print("[*] Mode scan tunggal (--no-reverse): hanya target awal")
    elif args.force_reverse:
        # Paksa reverse
        need_reverse = True
        print("[*] Mode reverse (--reverse): cari domain lain di IP yang sama")
    elif args.mode == "reverseonly":
        need_reverse = True
    elif args.mode in reverse_modes:
        # Default perilaku lama: reverse untuk mode berbahaya
        need_reverse = True

    domains = [f"http://{target}"]
    if need_reverse:
        reversed_domains = reverse_mode(target, proxy=args.proxy, verbose=args.verbose)
        if reversed_domains:
            domains = reversed_domains
        else:
            print("[!] Tidak ada domain dari reverse, pakai target awal saja.")
            domains = [f"http://{target}"]

    # Gunakan orchestrator Scanner (profesional)
    scanner = Scanner(target, args.mode, proxy=args.proxy,
                      verbose=args.verbose, session=session)
    scanner.run(domains=domains)
    print("[+] DONE!")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print_banner()
        sys.exit(1)
    main()