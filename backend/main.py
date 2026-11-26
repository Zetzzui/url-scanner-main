import asyncio
import base64
import ipaddress
import logging
import os
import socket
import time
from collections import OrderedDict, defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlunparse

import httpx
import whois
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from twilio.request_validator import RequestValidator
from twilio.rest import Client as TwilioClient
from twilio.twiml.messaging_response import MessagingResponse

from links import extract_urls, normalize_url, registered_domain
from scoring import calculate_risk_score, get_verdict, url_warnings

load_dotenv()
log = logging.getLogger("url-scanner")

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GSB_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
TWILIO_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")
# The exact public URL Twilio posts to (e.g. your ngrok https URL + /sms). Needed for the
# signature check when a proxy makes the URL seen here differ from the one Twilio used.
TWILIO_WEBHOOK_URL = os.getenv("TWILIO_WEBHOOK_URL")
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",") if o.strip()]
VT_REQUESTS_PER_MINUTE = int(os.getenv("VT_REQUESTS_PER_MINUTE", "4"))  # free tier: 4/min
SCANS_PER_HOUR_PER_CLIENT = int(os.getenv("SCANS_PER_HOUR_PER_CLIENT", "60"))
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "3600"))

MAX_REDIRECTS = 5
MAX_BULK_URLS = 20
MAX_SMS_LINKS = 5
SMS_MAX_CHARS = 1500  # Twilio's hard limit is 1600
VT_POLL_ATTEMPTS = 4
VT_POLL_DELAY = 5  # seconds; the rate limiter may add more
VT_STALE_DAYS = 30
CACHE_MAX_ENTRIES = 1000

VERDICT_LABELS = {
    "dangerous": "DANGEROUS",
    "suspicious": "SUSPICIOUS",
    "clean": "NO THREATS FOUND",
    "unknown": "COULD NOT VERIFY",
    "error": "ERROR",
}


@asynccontextmanager
async def lifespan(_app):
    if not VT_KEY:
        raise RuntimeError("VIRUSTOTAL_API_KEY is not set. Add it to backend/.env before starting the server.")
    yield


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def unhandled_error(_request, _exc):
    log.exception("Unhandled error")
    return JSONResponse(status_code=500, content={"detail": "Internal error while scanning."})


# --- Limits and caching -----------------------------------------------------------------------


class RateLimiter:
    """Spaces calls out so no more than `per_minute` start in any one minute."""

    def __init__(self, per_minute):
        self.interval = 60 / per_minute
        self.lock = asyncio.Lock()
        self.next_slot = 0.0

    async def wait(self):
        async with self.lock:
            now = time.monotonic()
            delay = self.next_slot - now
            self.next_slot = max(now, self.next_slot) + self.interval
        if delay > 0:
            await asyncio.sleep(delay)


vt_limiter = RateLimiter(VT_REQUESTS_PER_MINUTE)
_client_hits = defaultdict(deque)
_cache = OrderedDict()


def check_client_quota(key, cost=1):
    """Allow each client (IP address or phone number) a fixed number of URL scans per hour."""
    now = time.monotonic()
    hits = _client_hits[key]
    while hits and now - hits[0] > 3600:
        hits.popleft()
    if len(hits) + cost > SCANS_PER_HOUR_PER_CLIENT:
        raise HTTPException(429, f"Scan limit reached ({SCANS_PER_HOUR_PER_CLIENT} links per hour). Try again later.")
    hits.extend([now] * cost)


def cache_get(key):
    entry = _cache.get(key)
    if entry is None:
        return None
    stored_at, value = entry
    if time.monotonic() - stored_at > CACHE_TTL_SECONDS:
        del _cache[key]
        return None
    _cache.move_to_end(key)
    return value


def cache_put(key, value):
    _cache[key] = (time.monotonic(), value)
    _cache.move_to_end(key)
    while len(_cache) > CACHE_MAX_ENTRIES:
        _cache.popitem(last=False)


# --- Following redirects safely -----------------------------------------------------------------


def _resolve_public_ip(host):
    """One IP for the host, or None unless every address it resolves to is on the public internet."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return None
    ips = {info[4][0].split("%")[0] for info in infos}
    if not ips or not all(ipaddress.ip_address(ip).is_global for ip in ips):
        return None
    ipv4 = sorted(ip for ip in ips if ":" not in ip)
    return ipv4[0] if ipv4 else sorted(ips)[0]


async def _request_pinned(client, method, url):
    """Send a request to the IP address we already checked, rather than letting httpx look the
    name up again (a second lookup could return an internal address: DNS rebinding).
    Only the headers are read. Returns None if the target isn't a public address."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    ip = await asyncio.to_thread(_resolve_public_ip, parsed.hostname)
    if ip is None:
        return None
    host = parsed.hostname.encode("idna").decode()
    port = parsed.port  # raises ValueError for a malformed port
    ip_host = f"[{ip}]" if ":" in ip else ip
    target = urlunparse(parsed._replace(netloc=ip_host + (f":{port}" if port else "")))
    request = client.build_request(
        method,
        target,
        headers={"Host": host + (f":{port}" if port else "")},
        # TLS still uses (and verifies the certificate for) the real hostname.
        extensions={"sni_hostname": host} if parsed.scheme == "https" else {},
        timeout=5,
    )
    response = await client.send(request, follow_redirects=False, stream=True)
    await response.aclose()
    return response


async def _probe(client, url):
    """HEAD first. Some servers reject HEAD or only redirect on GET, so then try a GET whose body is never downloaded."""
    response = None
    for method in ("HEAD", "GET"):
        try:
            response = await _request_pinned(client, method, url)
        except (httpx.HTTPError, ValueError, UnicodeError):
            response = None
        if response is None:
            continue
        if response.is_redirect or response.status_code < 400:
            return response
    return response


async def expand_url(client, url):
    """Follow redirects (e.g. from link shorteners) to where the link really goes, never touching internal addresses."""
    current = url
    for _ in range(MAX_REDIRECTS):
        response = await _probe(client, current)
        location = response.headers.get("location") if response is not None else None
        if response is None or not response.is_redirect or not location:
            break
        current = urljoin(current, location)
    return current


# --- Checks -------------------------------------------------------------------------------------


class VirusTotalError(Exception):
    pass


async def _vt_request(client, method, path, **kwargs):
    await vt_limiter.wait()
    response = await client.request(
        method, f"https://www.virustotal.com/api/v3{path}", headers={"x-apikey": VT_KEY}, timeout=15, **kwargs
    )
    if response.status_code == 429:
        raise VirusTotalError("VirusTotal rate limit reached. Try again in a minute.")
    if response.status_code == 401:
        raise VirusTotalError("VirusTotal rejected the API key.")
    return response


async def _vt_submit_and_wait(client, url):
    response = await _vt_request(client, "POST", "/urls", data={"url": url})
    if response.status_code != 200:
        raise VirusTotalError(f"VirusTotal submission failed (HTTP {response.status_code}).")
    analysis_id = response.json()["data"]["id"]
    for _ in range(VT_POLL_ATTEMPTS):
        await asyncio.sleep(VT_POLL_DELAY)
        response = await _vt_request(client, "GET", f"/analyses/{analysis_id}")
        if response.status_code == 200:
            attrs = response.json()["data"]["attributes"]
            if attrs.get("status") == "completed":
                return attrs["stats"]
    raise VirusTotalError("VirusTotal is still analyzing this link. Try again in a minute.")


async def check_virustotal(client, url):
    # Reuse VirusTotal's existing report if it's recent (instant, no queue wait).
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    response = await _vt_request(client, "GET", f"/urls/{url_id}")
    old_stats = None
    if response.status_code == 200:
        attrs = response.json()["data"]["attributes"]
        old_stats = attrs.get("last_analysis_stats")
        last_scanned = attrs.get("last_analysis_date")
        if old_stats and last_scanned and time.time() - last_scanned < VT_STALE_DAYS * 86400:
            return old_stats
    elif response.status_code != 404:
        raise VirusTotalError(f"VirusTotal lookup failed (HTTP {response.status_code}).")

    # No report, or an old one: ask for a fresh scan. If that fails, an old report beats nothing.
    try:
        return await _vt_submit_and_wait(client, url)
    except VirusTotalError:
        if old_stats:
            return old_stats
        raise


async def check_google_safe_browsing(client, urls):
    if not GSB_KEY:
        return None  # no key configured: skip this check
    payload = {
        "client": {"clientId": "url-scanner", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }
    response = await client.post(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}", json=payload, timeout=10
    )
    response.raise_for_status()
    return len(response.json().get("matches", [])) > 0


def check_domain_age(url):
    """Days since the registered domain (example.co.uk, not login.example.co.uk) was created, or None."""
    domain = registered_domain(url)
    if not domain:
        return None
    try:
        created = whois.whois(domain).creation_date
    except Exception:
        return None
    if isinstance(created, list):
        created = min((d for d in created if isinstance(d, datetime)), default=None)
    if not isinstance(created, datetime):
        return None
    created = created.replace(tzinfo=timezone.utc) if created.tzinfo is None else created.astimezone(timezone.utc)
    return (datetime.now(timezone.utc) - created).days


async def analyze(client, url):
    """Single source of truth for scanning one URL. Never raises: failed checks are listed in `errors`."""
    cached = cache_get(url)
    if cached is not None:
        return {**cached, "cached": True}

    final_url = await expand_url(client, url)
    # Scan where the link actually lands, not just the (possibly shortened) original.
    vt_result, gsb_result, age_result = await asyncio.gather(
        check_virustotal(client, final_url),
        check_google_safe_browsing(client, list(dict.fromkeys([url, final_url]))),
        asyncio.wait_for(asyncio.to_thread(check_domain_age, final_url), timeout=15),
        return_exceptions=True,
    )

    errors = []
    vt_stats = gsb_flagged = domain_age_days = None
    if isinstance(vt_result, Exception):
        errors.append(str(vt_result) if isinstance(vt_result, VirusTotalError) else "VirusTotal check failed.")
    else:
        vt_stats = vt_result
    if isinstance(gsb_result, Exception):
        errors.append("Google Safe Browsing check failed.")
    else:
        gsb_flagged = gsb_result
    if not isinstance(age_result, Exception):
        domain_age_days = age_result

    warnings = {w["code"]: w for w in url_warnings(url) + url_warnings(final_url)}
    warnings = list(warnings.values())

    if gsb_flagged is None:
        gsb_status = "error" if isinstance(gsb_result, Exception) else "not checked"
    else:
        gsb_status = "flagged" if gsb_flagged else "clean"

    result = {
        "url": url,
        "final_url": final_url,
        "verdict": get_verdict(vt_stats, gsb_flagged, domain_age_days, warnings),
        "risk_score": calculate_risk_score(vt_stats, gsb_flagged, domain_age_days, warnings),
        "virustotal": vt_stats,
        "google_safe_browsing": gsb_status,
        "domain_age_days": domain_age_days,
        "warnings": [w["message"] for w in warnings],
        "errors": errors,
        "cached": False,
    }
    if not errors:
        cache_put(url, result)
    return result


def error_result(url, message):
    return {"url": url, "verdict": "error", "risk_score": None, "errors": [message], "warnings": []}


# --- Endpoints ----------------------------------------------------------------------------------


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class BulkScanRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=MAX_BULK_URLS)


class ExtractRequest(BaseModel):
    text: str = Field(max_length=200_000)


def client_key(request):
    return request.client.host if request.client else "unknown"


@app.get("/")
def root():
    return {"status": "URL scanner backend running"}


@app.post("/scan")
async def scan_url(body: ScanRequest, request: Request):
    url = normalize_url(body.url)
    if not url:
        raise HTTPException(422, "That doesn't look like a web address.")
    check_client_quota(client_key(request))
    async with httpx.AsyncClient() as client:
        return await analyze(client, url)


@app.post("/scan/bulk")
async def scan_bulk(body: BulkScanRequest, request: Request):
    urls = [(raw, normalize_url(raw)) for raw in body.urls]
    check_client_quota(client_key(request), cost=sum(1 for _, url in urls if url))
    async with httpx.AsyncClient() as client:

        async def scan_one(raw, url):
            if not url:
                return error_result(raw, "Not a valid web address.")
            return await analyze(client, url)

        results = await asyncio.gather(*(scan_one(raw, url) for raw, url in urls))
    return {"results": results}


@app.post("/extract-links")
async def extract_links(body: ExtractRequest):
    urls = extract_urls(body.text)
    return {"urls": urls, "count": len(urls)}


async def scan_and_text_back(to, urls):
    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(*(analyze(client, url) for url in urls))
    text = "\n\n".join(
        f"{r['url']}\n{VERDICT_LABELS[r['verdict']]} | Risk: {r['risk_score']}/100" for r in results
    )[:SMS_MAX_CHARS]
    try:
        twilio = TwilioClient(TWILIO_SID, TWILIO_TOKEN)
        await asyncio.to_thread(twilio.messages.create, to=to, from_=TWILIO_NUMBER, body=text)
    except Exception:
        log.exception("Could not send SMS results")


@app.post("/sms")
async def receive_sms(request: Request, background: BackgroundTasks):
    if not (TWILIO_SID and TWILIO_TOKEN and TWILIO_NUMBER):
        raise HTTPException(503, "SMS scanning is not configured.")

    form = await request.form()
    params = {key: value for key, value in form.multi_items()}
    signature = request.headers.get("X-Twilio-Signature", "")
    if not RequestValidator(TWILIO_TOKEN).validate(TWILIO_WEBHOOK_URL or str(request.url), params, signature):
        raise HTTPException(403, "Request did not come from Twilio.")

    sender = str(form.get("From", ""))
    urls = extract_urls(str(form.get("Body", "")))[:MAX_SMS_LINKS]
    if not urls:
        reply = "No links found in your message."
    else:
        try:
            check_client_quota(f"sms:{sender}", cost=len(urls))
        except HTTPException:
            reply = "Too many scans from this number. Try again later."
        else:
            # Twilio waits only ~15 seconds for this reply, and scans can take longer,
            # so acknowledge now and text the results when they're ready.
            background.add_task(scan_and_text_back, sender, urls)
            reply = f"Scanning {len(urls)} link(s). Results will follow in a separate message."

    response = MessagingResponse()
    response.message(reply)
    return Response(content=str(response), media_type="application/xml")
