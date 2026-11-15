#!/usr/bin/env python3
import os
import random
import time

__developer__ = "_mywisdom & gunslinger_Abui"
__version__ = "6"
__date__ = "monday, 16 Nov 2026 $ 9:13 PM"

# ---------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

log = os.path.join(BASE_DIR, "logs", "darkjumper.log")
subpage_file = os.path.join(BASE_DIR, "data", "subpage.txt")
wordlist = os.path.join(BASE_DIR, "data", "wordlist.txt")
cgilist = os.path.join(BASE_DIR, "data", "cgilist.txt")
filerev = os.path.join(BASE_DIR, "data", "reverse.txt")

# FIX: pastikan direktori & file output ada agar tidak FileNotFoundError
for _d in (os.path.dirname(log), os.path.dirname(subpage_file)):
    os.makedirs(_d, exist_ok=True)
for _f in (log, subpage_file, filerev):
    if not os.path.exists(_f):
        open(_f, "a").close()
# wordlist & cgilist TIDAK dibuat otomatis — user harus menyediakan isinya

proxy = None
verbose = False
autobrute = False
subpages = "yes"
niktoscan = "no"        # Set "yes" untuk mengaktifkan sqlmap
port_range = "1-1000"   # FIX: default untuk mode portscan

# ---------------------------------------------------------------
# User agents
# ---------------------------------------------------------------
ouruseragent = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/94.0.4606.71",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
]

# ---------------------------------------------------------------
# SQLi / disclosure patterns
# ---------------------------------------------------------------
mysqli1 = "You have an error in your SQL syntax"
accesqli1 = "Microsoft JET Database"
mssqli1 = "Microsoft SQL Server"
oracle = "ORA-"
pathdisclosure1 = "/home/"
pathdisclosure2 = "/var/"

# ---------------------------------------------------------------
# Reverse IP settings
# ---------------------------------------------------------------
# HackerTarget reverse-IP API (gratis, 50 query/hari)
machine = "https://api.hackertarget.com/reverseiplookup/?q="

# Fallback RapidDNS (scraping, tanpa API key)
machine_fallback = "https://rapiddns.io/sameip/"
saring = "/whois/"
saringan = ["1", "2", "3", "4", "5", "6", "7", "8", "9"]

# ---------------------------------------------------------------
# Banner
# FIX: pakai raw string (r"""...""") agar backslash tidak perlu di-escape dobel
# ---------------------------------------------------------------
darkjumperface2 = r"""
################################################################
#       .___             __          _______       .___        #
#     __| _/____ _______|  | __ ____ \   _  \    __| _/____    #
#    / __ |\__  \\_  __ \  |/ // ___\ /  /_\  \  / __ |/ __ \   #
#   / /_/ | / __ \|  | \/    <\  \___\  \_/   \/ /_/ \  ___/   #
#   \____ |(______/__|  |__|_ \\_____>\_____  /\_____|\____\   #
#        \/                  \/             \/                 #
#                   ___________   ______  _  __                #
#                 _/ ___\_  __ \_/ __ \ \/ \/ /                #
#                 \  \___|  | \/\  ___\     /                 #
#                  \___  >__|    \___  >\/\_/                  #
#      est.2007        \/            \/   DarkJumper   #
################################################################
""" + f"""
Darkjumper.py version {__version__}
Developed by: {__developer__}
Date release: {__date__}
"""

# ---------------------------------------------------------------
# Instance `var` — dipakai oleh semua modul via:
#     from config.var import var
# Semua atribut di atas di-attach ke instance ini.
# ---------------------------------------------------------------
class _VarNamespace:
    """Namespace dinamis: attribute lookup fallback ke globals() modul ini."""
    def __getattr__(self, name):
        try:
            return globals()[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        globals()[name] = value


var = _VarNamespace()

# ---------------------------------------------------------------
# Report output
# ---------------------------------------------------------------
output_json = "reports/findings.json"
output_csv = "reports/findings.csv"
output_sarif = "reports/findings.sarif"

# ---------------------------------------------------------------
# WAF signatures (header-based detection)
# ---------------------------------------------------------------
waf_signatures = {
    "Cloudflare": ["cloudflare", "cf-ray"],
    "Sucuri": ["x-sucuri-id", "sucuri"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "AWS WAF": ["awselb", "x-amzn"],
    "Akamai": ["akamai", "x-akamai"],
    "Imperva": ["imperva", "x-iinfo"],
    "F5 BIG-IP": ["big-ip", "bigip"],
    "Barracuda": ["barra", "barracuda"],
}

# ---------------------------------------------------------------
# AI Verification (LLM filter false positive)
# ---------------------------------------------------------------
ai_verify = False
ai_provider = "deepseek"
ai_model = "deepseek-chat"
ai_api_key = ""
ai_base_url = ""
ai_timeout = 30

common_params = ["id", "page", "file", "path", "url", "view", "action", "cmd", "exec", "query", "search", "q", "keyword", "name", "user", "username", "email", "lang", "language", "locale", "redirect", "return", "next", "callback", "p", "page_id", "cat", "author", "s", "m", "attachment_id", "feed", "tag", "route", "controller", "method", "slug", "format", "filter", "sort", "limit", "offset"]

wp_params = ["p", "page_id", "cat", "author", "s", "m", "attachment_id", "feed", "tag"]
