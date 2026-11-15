#!/usr/bin/env python3
"""HTTP client dengan retry, timeout, rate limiting, dan WAF detection."""
import time
import threading

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config.var import var


_waf_cache = {}
_waf_lock = threading.Lock()


class HttpClient:
    """HTTP client dengan retry, rate limiting, dan session management."""

    def __init__(self, proxy=None, session=None, verbose=False, timeout=10):
        self.proxy = proxy
        self.session = session or requests.Session()
        self.verbose = verbose
        self.timeout = timeout
        self.proxies = {"http": proxy, "https": proxy} if proxy else None

        # Retry strategy (3x dengan backoff)
        retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _apply_delay(self):
        delay = getattr(var, "delay", 0.0)
        if delay > 0:
            time.sleep(delay)

    def request(self, method, url, **kwargs):
        """Request dengan retry, delay, dan error handling."""
        self._apply_delay()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("proxies", self.proxies)

        try:
            r = self.session.request(method, url, **kwargs)
            if self.verbose:
                print(f"[HTTP] {method} {url} -> {r.status_code} ({len(r.text)} bytes)")
            return r
        except requests.RequestException as e:
            if self.verbose:
                print(f"[HTTP] {method} {url} -> ERROR: {e}")
            return None

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def head(self, url, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def detect_waf(self, target):
        """Deteksi WAF berdasarkan header/body."""
        with _waf_lock:
            if target in _waf_cache:
                return _waf_cache[target]

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        for scheme in ("https", "http"):
            try:
                r = self.session.get(
                    f"{scheme}://{target}", headers=headers, timeout=10,
                    verify=False, proxies=self.proxies
                )
                headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
                body_lower = r.text.lower()

                for waf_name, signatures in var.waf_signatures.items():
                    for sig in signatures:
                        if sig in headers_lower or sig in body_lower:
                            with _waf_lock:
                                _waf_cache[target] = waf_name
                            if self.verbose:
                                print(f"[WAF] Terdeteksi: {waf_name}")
                            return waf_name
                break
            except requests.RequestException:
                continue

        with _waf_lock:
            _waf_cache[target] = None
        return None

    def detect_tech(self, target):
        """Deteksi teknologi web dari header/body."""
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        for scheme in ("https", "http"):
            try:
                r = self.session.get(
                    f"{scheme}://{target}", headers=headers, timeout=10,
                    verify=False, proxies=self.proxies
                )
                h = {k.lower(): v.lower() for k, v in r.headers.items()}
                body = r.text.lower()
                server = h.get("server", "")
                xpowered = h.get("x-powered-by", "")

                if "wp-content" in body or "wordpress" in body or "wp-json" in body:
                    return "wordpress"
                if "laravel" in body or "laravel_session" in str(h):
                    return "laravel"
                if "django" in body or "csrftoken" in str(h):
                    return "django"
                if "rails" in body or "_session_id" in str(h):
                    return "rails"
                if "jsessionid" in str(h) or "jsp" in body:
                    return "jsp"
                if "asp.net" in server or "aspnet" in str(h):
                    return "aspnet"
                if "php" in xpowered or "php" in server:
                    return "php"
                return "unknown"
            except requests.RequestException:
                continue
        return "unknown"
