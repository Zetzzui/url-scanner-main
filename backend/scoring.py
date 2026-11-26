"""Risk score, verdict and URL-shape warnings. Pure functions, no network access."""
import ipaddress
import re
from urllib.parse import urlparse

from links import tld_extract

# TLDs that are cheap or free and turn up disproportionately in phishing and malware reports.
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country",
    "kim", "work", "rest", "cam", "icu", "buzz", "monster", "cyou", "sbs",
}
_LOGIN_WORDS = re.compile(r"login|log-in|signin|sign-in|verify|account|password|banking|wallet", re.IGNORECASE)

MAX_WARNING_POINTS = 30


def url_warnings(url):
    """Red flags in the URL itself. Returns a list of {"code", "message", "points"}."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    warnings = []

    def add(code, message, points):
        warnings.append({"code": code, "message": message, "points": points})

    try:
        ipaddress.ip_address(host)
        add("ip_host", "Link points to a raw IP address instead of a domain name", 20)
    except ValueError:
        pass
    if parsed.username is not None:
        add("userinfo", "Link contains '@', which can hide the real destination", 20)
    if any(label.startswith("xn--") for label in host.split(".")):
        add("punycode", "Domain uses non-Latin characters that can imitate a real brand", 15)
    parts = tld_extract(host)
    if parts.subdomain and parts.subdomain.count(".") >= 2:
        add("many_subdomains", "Unusually many subdomains", 10)
    if parts.suffix.split(".")[-1].lower() in SUSPICIOUS_TLDS:
        add("suspicious_tld", f"The .{parts.suffix} ending is common in scam links", 10)
    if parsed.scheme == "http" and _LOGIN_WORDS.search(host + parsed.path):
        add("http_login", "Login or account page without HTTPS encryption", 10)
    return warnings


def calculate_risk_score(vt_stats, gsb_flagged, domain_age_days, warnings):
    vt_stats = vt_stats or {}
    score = 0
    if gsb_flagged:
        score += 50
    score += min(vt_stats.get("malicious", 0) * 10, 40)
    score += min(vt_stats.get("suspicious", 0) * 5, 20)
    if domain_age_days is None:
        score += 5  # scam domains often hide or lack WHOIS data
    elif domain_age_days < 30:
        score += 20
    elif domain_age_days < 180:
        score += 10
    score += min(sum(w["points"] for w in warnings), MAX_WARNING_POINTS)
    return min(score, 100)


def get_verdict(vt_stats, gsb_flagged, domain_age_days, warnings):
    """'dangerous', 'suspicious', 'clean' (no threats found) or 'unknown' (VirusTotal unavailable)."""
    stats = vt_stats or {}
    if gsb_flagged or stats.get("malicious", 0) > 0:
        return "dangerous"
    if (
        stats.get("suspicious", 0) > 0
        or (domain_age_days is not None and domain_age_days < 30)
        or sum(w["points"] for w in warnings) >= 20
    ):
        return "suspicious"
    if vt_stats is None:
        return "unknown"
    return "clean"
