#!/usr/bin/env python3
import socket
import threading
from queue import Queue, Empty

from config.var import var


# FIX: mapping port -> nama service umum untuk output lebih informatif
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
}


def _grab_banner(target, port, timeout=2):
    """
    FIX: ambil banner dengan aman.
    - Beberapa service (HTTP/HTTPS) tidak mengirim banner sampai kita kirim request.
    - recv() bisa hang jika server diam → beri timeout lebih pendek.
    """
    banner = b""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        if result != 0:
            sock.close()
            return None

        # Kirim probe minimal untuk service yang butuh request dulu
        if port in (80, 8080):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 443:
            # Jangan kirim apa-apa; TLS handshake akan gagal di plain recv
            # tapi setidaknya kita tahu port terbuka
            banner = b"<TLS handshake required>"
        elif port in (21, 22, 23, 25, 110, 143, 3306, 5432, 6379):
            # Service ini biasanya langsung kirim banner
            pass

        try:
            banner = sock.recv(1024)
        except socket.timeout:
            banner = banner or b"<no banner / timeout>"
        sock.close()
    except (socket.gaierror, OSError) as e:
        return f"<error: {type(e).__name__}>".encode()
    return banner


def scan_daemon(target, verbose=False):
    """Scan for daemon information."""
    log_file = var.log
    # FIX: tambah port umum lain
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080]
    queue = Queue()
    threads = []

    print(f"[+] Scanning daemon info on {target}")
    with open(log_file, "a") as filelog:
        filelog.write(f"\n[+] Scanning daemon info on {target}\n")

    def worker():
        while True:
            # FIX: hindari race queue.empty() vs get()
            try:
                port = queue.get(timeout=1)
            except Empty:
                break

            try:
                service = COMMON_SERVICES.get(port, "unknown")
                banner_bytes = _grab_banner(target, port)

                if banner_bytes is None:
                    if verbose:
                        print(f"[-] Port {port} ({service}) closed")
                else:
                    banner = banner_bytes.decode(errors="ignore").strip()
                    # Ambil baris pertama saja agar rapi
                    first_line = banner.splitlines()[0] if banner else ""
                    label = f"Port {port} ({service}) open"
                    if first_line:
                        print(f"[!] {label}: {first_line}")
                    else:
                        print(f"[!] {label}")
                    with open(log_file, "a") as filelog:
                        filelog.write(f"[!] {label}: {first_line}\n")

            finally:
                # FIX: task_done dijamin dipanggil
                queue.task_done()

    for port in ports:
        queue.put(port)

    # FIX: thread_count tidak melebihi jumlah task, minimal 1
    thread_count = min(10, len(ports))
    for _ in range(thread_count):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"[+] Daemon scan finished for {target}")