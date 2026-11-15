#!/usr/bin/env python3
"""Orchestrator scan: koordinasi semua modul."""
import base64
import sys

from core.http_client import HttpClient
from core.findings import findings
from core.logger import get_logger

from config.var import var
from modules import adminpath, darkcgi, daemoninfo, devilzc0de, ftpbrute, subscan


log = get_logger()

# Mode yang membutuhkan WAF detection
DANGEROUS_MODES = ("injection", "inclusion", "full", "enum", "ftpanon")


class Scanner:
    """Orchestrator untuk semua mode scanning."""

    def __init__(self, target, mode, proxy=None, verbose=False, session=None):
        self.target = target
        self.mode = mode
        self.proxy = proxy
        self.verbose = verbose
        self.session = session
        self.client = HttpClient(proxy=proxy, session=session, verbose=verbose)

    def run(self, domains=None):
        """Jalankan scan berdasarkan mode (dengan error handling)."""
        try:
            self._run_internal(domains)
        except Exception as e:
            import traceback
            print(f"[!] Scanner error: {e}")
            if self.verbose:
                traceback.print_exc()

    def _run_internal(self, domains=None):
        """Internal run."""
        domains = domains or [f"http://{self.target}"]

        # WAF detection (selalu, dengan error handling)
        try:
            waf = self.client.detect_waf(self.target)
            if waf:
                log.warning(f"WAF terdeteksi: {waf} — mode {self.mode} mungkin diblokir")
        except Exception as e:
            if self.verbose:
                print(f"[!] WAF detection error: {e}")

        # Tech detection (selalu, dengan error handling)
        try:
            tech = self.client.detect_tech(self.target)
            if tech != "unknown":
                log.info(f"Teknologi terdeteksi: {tech}")
        except Exception as e:
            if self.verbose:
                print(f"[!] Tech detection error: {e}")

        # Dispatch ke modul
        if self.mode in ("injection", "full"):
            for domain in domains:
                log.info(f"Injection scan: {domain}")
                devilzc0de.scan_vulnerabilities(
                    domain, types=["sqli", "blind"],
                    proxy=self.proxy, verbose=self.verbose, session=self.session
                )
                if var.subpages == "yes":
                    subscan.scan_subpages(domain, proxy=self.proxy, verbose=self.verbose, session=self.session)

        if self.mode in ("inclusion", "full"):
            for domain in domains:
                log.info(f"Inclusion scan: {domain}")
                devilzc0de.scan_vulnerabilities(
                    domain, types=["rfi", "lfi", "rce"],
                    proxy=self.proxy, verbose=self.verbose, session=self.session
                )

        if self.mode == "cgidirs":
            darkcgi.scan_cgi(self.target, proxy=self.proxy, verbose=self.verbose)
        if self.mode == "ftpanon":
            ftpbrute.check_anonymous(self.target, verbose=self.verbose)
        if self.mode == "scanadminpath":
            if self.verbose:
                print(f"[DEBUG] Memanggil adminpath untuk {self.target}")
            adminpath.scan_admin_paths(self.target, proxy=self.proxy, verbose=self.verbose)
        if self.mode == "daemoninfo":
            daemoninfo.scan_daemon(self.target, verbose=self.verbose)

        # Fallback mode
        if self.mode in ("headerinfo", "checkip", "converter", "portscan", "reverseonly", "enum"):
            self._fallback_mode()

        # Ringkasan
        summary = findings.summary()
        if summary:
            log.info(f"Ringkasan temuan: {summary}")
            findings.export_csv()
            findings.export_sarif()

    def _fallback_mode(self):
        """Fallback untuk mode yang belum diimplementasi di Scanner."""
        if self.mode == "headerinfo":
            try:
                r = self.client.head(f"https://{self.target}")
                if r is None:
                    r = self.client.head(f"http://{self.target}")
                if r is not None:
                    print(r.headers)
                else:
                    print("[!] Error fetching headers")
            except Exception as e:
                print(f"[!] Error fetching headers: {e}")

        elif self.mode == "checkip":
            from darkjumper import check_ip
            check_ip(proxy=self.proxy)

        elif self.mode == "converter":
            data = input("[-] Input data to encode: ")
            print(f"[+] Hex: {data.encode().hex()}")
            print(f"[+] Base64: {base64.b64encode(data.encode()).decode()}")

        elif self.mode == "portscan":
            from darkjumper import port_scan
            try:
                start_port, end_port = map(int, getattr(var, "port_range", "1-1000").split("-"))
                port_scan(self.target, start_port, end_port, verbose=self.verbose)
            except (ValueError, AttributeError):
                print("[!] Port range format: start-end")

        elif self.mode == "reverseonly":
            from darkjumper import reverse_mode
            reverse_mode(self.target, proxy=self.proxy, verbose=self.verbose)

        elif self.mode == "enum":
            from darkjumper import enum_scan
            enum_scan(self.target, verbose=self.verbose)
