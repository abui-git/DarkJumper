"""Smoke test: pastikan semua fungsi bisa di-import & signature cocok."""
import inspect
import os
import sys
sys.path.insert(0, ".")

from config.var import var
from modules import adminpath, darkcgi, daemoninfo, devilzc0de, ftpbrute, subscan


def check(fn, expected_params):
    sig = inspect.signature(fn)
    params = list(sig.parameters)
    for p in expected_params:
        assert p in params, f"{fn.__name__}: parameter '{p}' hilang (ada: {params})"
    print(f"[OK] {fn.__name__}{sig}")


check(adminpath.scan_admin_paths, ["target", "proxy", "verbose"])
check(darkcgi.scan_cgi, ["target", "proxy", "verbose"])
check(daemoninfo.scan_daemon, ["target", "verbose"])
check(devilzc0de.scan_vulnerabilities, ["url", "types", "proxy", "verbose"])
check(ftpbrute.check_anonymous, ["hostname", "verbose"])
check(ftpbrute.brute_force, ["hostname", "username", "wordlist", "verbose"])
check(subscan.scan_subpages, ["target", "proxy", "verbose"])

required_attrs = [
    "log", "filerev", "subpage_file", "wordlist", "cgilist",
    "ouruseragent", "mysqli1", "accesqli1", "mssqli1", "oracle",
    "saring", "saringan", "machine", "subpages", "darkjumperface2",
    "niktoscan", "autobrute", "proxy", "verbose", "port_range",
]
missing = [a for a in required_attrs if not hasattr(var, a)]
assert not missing, f"var kehilangan atribut: {missing}"
print(f"[OK] var punya semua {len(required_attrs)} atribut")

assert isinstance(var.ouruseragent, list) and len(var.ouruseragent) > 0
assert isinstance(var.saringan, list)
assert isinstance(var.port_range, str) and "-" in var.port_range
print("[OK] Tipe data var valid")

for p in [var.log, var.subpage_file, var.filerev]:
    assert os.path.exists(p), f"File output tidak ada: {p}"
print("[OK] File output sudah dibuat otomatis oleh var.py")

print("\n=== SEMUA SMOKE TEST LULUS ===")
