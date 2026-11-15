#!/usr/bin/env python3
"""AI Verifier: gunakan LLM untuk memvalidasi temuan (filter false positive)."""
import json
import os
import time

import requests

from config.var import var


SYSTEM_PROMPT = """You are a security analyst verifying vulnerability scanner findings.
Given a payload and the HTTP response, determine if this is a TRUE POSITIVE or FALSE POSITIVE.

Rules:
- TRUE POSITIVE: response contains clear evidence of the vulnerability (e.g., SQL error, file content, command output).
- FALSE POSITIVE: response is a generic error, redirect, login page, or unrelated content.

Answer ONLY with JSON:
{"verdict": "TRUE" | "FALSE", "reason": "short explanation"}"""


PROVIDER_CONFIG = {
    "deepseek": {"base_url": "https://api.deepseek.com/v1", "default_model": "deepseek-chat"},
    "groq": {"base_url": "https://api.groq.com/openai/v1", "default_model": "openai/gpt-oss-20b"},
    "openai": {"base_url": "https://api.openai.com/v1", "default_model": "gpt-4o-mini"},
    "ollama": {"base_url": "http://localhost:11434/v1", "default_model": "qwen2.5-coder:0.5b"},
}


def _get_provider_config():
    """Ambil konfigurasi provider AI."""
    provider = getattr(var, "ai_provider", "deepseek")
    cfg = PROVIDER_CONFIG.get(provider, PROVIDER_CONFIG["deepseek"]).copy()

    if getattr(var, "ai_base_url", ""):
        cfg["base_url"] = var.ai_base_url
    if getattr(var, "ai_model", ""):
        cfg["model"] = var.ai_model
    else:
        cfg["model"] = cfg["default_model"]

    cfg["api_key"] = os.environ.get("DARKJUMPER_AI_KEY", getattr(var, "ai_api_key", ""))
    cfg["timeout"] = getattr(var, "ai_timeout", 30)
    cfg["provider"] = provider
    return cfg


def _call_llm(messages, retries=2):
    """Panggil LLM API dengan retry."""
    cfg = _get_provider_config()

    if cfg["provider"] != "ollama" and not cfg["api_key"]:
        print("[AI] API key kosong — set DARKJUMPER_AI_KEY")
        return None

    headers = {
        "Authorization": f"Bearer {cfg['api_key'] or 'ollama'}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": cfg["model"],
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": 200,
    }

    for attempt in range(retries + 1):
        try:
            r = requests.post(
                f"{cfg['base_url']}/chat/completions",
                headers=headers, json=payload, timeout=cfg["timeout"],
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
            if r.status_code == 429 and attempt < retries:
                wait = 2 ** attempt
                print(f"[AI] Rate limit, retry dalam {wait}s...")
                time.sleep(wait)
                continue
            print(f"[AI] API error: {r.status_code} — {r.text[:200]}")
            return None
        except requests.RequestException as e:
            if attempt < retries:
                time.sleep(2 ** attempt)
                continue
            print(f"[AI] Request failed: {e}")
            return None

    return None


def _parse_verdict(result):
    """Parse JSON verdict dari response LLM."""
    if not result:
        return None, None

    result = result.strip()

    # Ekstrak JSON dari markdown code block
    if "```json" in result:
        result = result.split("```json")[1].split("```")[0]
    elif "```" in result:
        result = result.split("```")[1].split("```")[0]

    # Cari JSON object di tengah teks
    try:
        return json.loads(result)
    except json.JSONDecodeError:
        pass

    # Fallback: cari { ... } pertama
    start = result.find("{")
    end = result.rfind("}")
    if start != -1 and end != -1:
        try:
            return json.loads(result[start:end + 1])
        except json.JSONDecodeError:
            pass

    return None


def verify_finding(vuln_type, payload, response_text, verbose=False):
    """
    Verifikasi temuan dengan LLM.
    Return: (verdict: bool, reason: str)
    """
    if not getattr(var, "ai_verify", False):
        return True, "AI verification disabled"

    snippet = response_text[:2000] if response_text else ""

    user_msg = f"""Vulnerability type: {vuln_type}
Payload used: {payload}
Response snippet (first 2000 chars):
---
{snippet}
---

Is this a TRUE POSITIVE or FALSE POSITIVE? Answer in JSON."""

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_msg},
    ]

    if verbose:
        cfg = _get_provider_config()
        print(f"[AI] Verifying {vuln_type} via {cfg['provider']}/{cfg['model']}...")

    result = _call_llm(messages)
    if not result:
        return True, "AI unavailable, keep finding (safety-first)"

    data = _parse_verdict(result)
    if not data:
        if verbose:
            print(f"[AI] Gagal parse: {result[:200]}")
        return True, "AI parse error, keep finding (safety-first)"

    verdict = str(data.get("verdict", "TRUE")).upper() == "TRUE"
    reason = data.get("reason", "")

    if verbose:
        print(f"[AI] Verdict: {'TRUE' if verdict else 'FALSE'} — {reason}")

    return verdict, reason
