# Darkjumper v5.7 — Professional + AI

Web Vulnerability Scanner dengan AI verification, SQLi/LFI detection,
auto-login, sqlmap integration, dan output SARIF untuk CI/CD.

> **Peringatan:** Gunakan **hanya** pada sistem yang kamu miliki atau punya izin tertulis.

---

## Fitur

- 13 mode scanning (reverse, headerinfo, portscan, daemoninfo, adminpath, cgidirs, ftpanon, injection, inclusion, full, enum, checkip, converter)
- AI verification (Groq, DeepSeek, OpenAI, Ollama)
- Output JSON, CSV, SARIF (CI/CD ready)
- WAF detection + tech detection
- Auto-login (CSRF token, DVWA)
- sqlmap integration (`--exploit dbs`)
- Validasi target (DNS)
- Rate limiting (`--delay`)
- Arsitektur `core/` (logger, http_client, findings, scanner, ai_verifier)
- Thread-safe findings

---

## Instalasi

```bash
pip install requests beautifulsoup4
