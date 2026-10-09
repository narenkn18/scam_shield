"""Link analysis: deterministic heuristics plus an optional Google Safe Browsing lookup.

The heuristics are plain code, so they are fast, free, testable and cannot be talked out of
their answer by a message that tries to manipulate the AI. Only the extracted URLs (never the
message text) are sent to Google Safe Browsing, and only if an API key is configured.
"""
import ipaddress
import json
import logging
import re
import urllib.request
from urllib.parse import urlsplit

import config

log = logging.getLogger("scamshield")

MAX_URLS = 5
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
SB_TIMEOUT_SECONDS = 3

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
    "ow.ly", "shorturl.at", "tiny.cc", "rebrand.ly", "t.ly",
}
RISKY_TLDS = {
    "xyz", "top", "click", "icu", "vip", "work", "support", "live", "shop", "club", "online",
    "site", "link", "tk", "ml", "ga", "cf", "gq", "cam", "rest", "monster", "buzz",
}
# A bare "name.tld" is only treated as a link for these endings. This avoids matching "Mr.Sharma" or "Rs.4,999".
BARE_TLDS = RISKY_TLDS | {"com", "in", "net", "org", "info", "co", "io", "app", "me", "cc", "biz", "pro", "ly", "gl"}
# Small, illustrative list of brand names scammers imitate, with the registrable domains we treat as official.
OFFICIAL = {
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbicard.com"},
    "hdfc": {"hdfcbank.com", "hdfc.com", "hdfclife.com"},
    "icici": {"icicibank.com", "icicidirect.com"},
    "axis": {"axisbank.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "amazon": {"amazon.in", "amazon.com"},
    "flipkart": {"flipkart.com"},
    "irctc": {"irctc.co.in"},
    "uidai": {"uidai.gov.in"},
    "jio": {"jio.com"},
    "airtel": {"airtel.in", "airtel.com"},
}
ACTION_WORDS = ("kyc", "verify", "login", "update", "secure", "otp", "refund", "claim", "reward")
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "nic", "edu"}

_URL_RE = re.compile(
    r"(?i)(?:https?://|www\.)[^\s<>\"'\]\[]+"
    r"|\b(?:[a-z0-9-]+\.)+(?:" + "|".join(sorted(BARE_TLDS)) + r")\b(?:/[^\s<>\"'\]\[]*)?"
)
_HOST_OK = re.compile(r"^[a-z0-9.-]{1,100}$")


def extract_urls(text):
    """Return up to MAX_URLS distinct URLs found in the text."""
    seen, out = set(), []
    for m in _URL_RE.finditer(text or ""):
        url = m.group(0).rstrip(".,;:!?)")
        key = url.lower()
        if key not in seen:
            seen.add(key)
            out.append(url)
        if len(out) == MAX_URLS:
            break
    return out


def _registrable(host):
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def analyze_url(url):
    """Inspect one URL. Returns host, a list of plain-language signals, and the Safe Browsing placeholder."""
    full = url if re.match(r"(?i)^https?://", url) else "http://" + url
    try:
        parts = urlsplit(full)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return {"url": url[:200], "host": "", "signals": ["The link is malformed"], "safe_browsing": "unchecked"}

    signals = []
    if host in SHORTENERS:
        signals.append("Shortened link: it hides the real destination")
    try:
        ipaddress.ip_address(host)
        signals.append("Uses a raw IP address instead of a website name")
    except ValueError:
        pass
    if "xn--" in host:
        signals.append("Look-alike (punycode) characters in the domain")
    if parts.username is not None:
        signals.append("Contains '@', which can hide the real website")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in RISKY_TLDS:
        signals.append(f"Unusual domain ending '.{tld}' that is common in scams")
    if host.count("-") >= 2:
        signals.append("Many hyphens in the domain, a common look-alike trick")
    if host.count(".") >= 4:
        signals.append("Unusually many sub-domains")
    registrable = _registrable(host)
    for brand, official in OFFICIAL.items():
        if brand in host and registrable not in official:
            signals.append(f"Uses the name '{brand}' but is not a domain we recognise as official")
            break
    if any(w in (parts.path or "").lower() or w in host for w in ACTION_WORDS):
        signals.append("Asks you to verify, update or claim something")
    if parts.scheme == "http" and re.match(r"(?i)^https?://", url):
        signals.append("Not encrypted (http, not https)")
    if port not in (None, 80, 443):
        signals.append(f"Unusual port number {port}")
    return {"url": url[:200], "host": host, "signals": signals, "safe_browsing": "unchecked"}


def _sb_request(urls):
    """POST to the Safe Browsing Lookup API (v4). Returns the parsed JSON. Raises on any failure."""
    body = json.dumps({
        "client": {"clientId": "scamshield", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }).encode()
    req = urllib.request.Request(
        f"{SAFE_BROWSING_URL}?key={config.SAFE_BROWSING_API_KEY}",
        data=body, headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=SB_TIMEOUT_SECONDS) as resp:  # noqa: S310 (fixed https URL)
        return json.load(resp)


def lookup_safe_browsing(urls):
    """Return {url: [threat types]} for flagged URLs, or None if unavailable (no key, error, timeout)."""
    if not config.SAFE_BROWSING_API_KEY or not urls:
        return None
    try:
        data = _sb_request(urls)
    except Exception as e:  # never let a reputation lookup break an analysis
        log.warning("Safe Browsing lookup failed: %s", type(e).__name__)  # type only: the URL contains the key
        return None
    flagged = {}
    for m in data.get("matches", []):
        flagged.setdefault(m.get("threat", {}).get("url", ""), []).append(m.get("threatType", "UNKNOWN"))
    return flagged


def check_urls(text, use_safe_browsing=True):
    """Extract URLs from text and analyze each one. Safe Browsing status is 'flagged', 'clear' or 'unchecked'."""
    results = [analyze_url(u) for u in extract_urls(text)]
    if not results or not use_safe_browsing:
        return results
    flagged = lookup_safe_browsing([r["url"] for r in results])
    if flagged is None:
        return results
    for r in results:
        if r["url"] in flagged:
            r["safe_browsing"] = "flagged"
            r["threats"] = flagged[r["url"]]
        else:
            r["safe_browsing"] = "clear"
    return results


def facts_for_prompt(results):
    """Short trusted facts for the model. Only the validated host is included, never the raw URL text."""
    lines = []
    for r in results:
        host = r["host"]
        if not _HOST_OK.match(host or ""):
            continue
        parts = list(r["signals"])
        if r["safe_browsing"] == "flagged":
            parts.insert(0, "FLAGGED by Google Safe Browsing as dangerous")
        elif r["safe_browsing"] == "clear":
            parts.append("not on Google Safe Browsing lists (this does not prove it is safe)")
        lines.append(f"- {host}: " + ("; ".join(parts) if parts else "no technical warning signs"))
    return "\n".join(lines)
