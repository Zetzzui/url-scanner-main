# URL Scanner

Checks whether a link is safe before you click it. It follows redirects (e.g. from link shorteners) to the real destination, then combines:

- **VirusTotal**: results from about 70 antivirus and URL-reputation engines
- **Google Safe Browsing** (optional): Google's list of phishing and malware sites
- **Domain age** from WHOIS: brand-new domains are a common sign of scams
- **URL red flags**: raw IP addresses, `@` tricks, lookalike (punycode) domains, risky TLDs, login pages without HTTPS

You can scan links from the web page (one link, a list of up to 20, or all links in a pasted email) or by texting them to a Twilio number.

## Setup

### Backend (FastAPI)

```bash
cd backend
python -m venv venv
venv\Scripts\activate            # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
copy .env.example .env           # macOS/Linux: cp .env.example .env
```

Fill in `VIRUSTOTAL_API_KEY` in `.env` (free at virustotal.com). The other keys are optional. Then:

```bash
uvicorn main:app --reload
```

The server refuses to start without a VirusTotal key.

### Frontend (Next.js)

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000. If the backend isn't at `http://127.0.0.1:8000`, copy `.env.example` to `.env.local` and set `NEXT_PUBLIC_API_URL`.

### SMS (optional)

1. Set the four `TWILIO_*` values in `backend/.env`.
2. Expose the backend publicly, e.g. `ngrok http 8000`.
3. In the Twilio console, set your number's "A message comes in" webhook to `https://<your-ngrok-host>/sms`, and put that same URL in `TWILIO_WEBHOOK_URL`. Requests are rejected unless their Twilio signature matches this URL.

The SMS endpoint replies right away ("Scanning…") and texts the results once they're ready, because Twilio only waits about 15 seconds for a reply.

## Limits

- **VirusTotal free tier:** 4 requests per minute and 500 per day. The backend spaces its calls out to stay under the per-minute limit. A link VirusTotal already knows costs 1 request. A new link costs about 3–6, because it has to be submitted and then checked until the analysis finishes. With a paid key, raise `VT_REQUESTS_PER_MINUTE`.
- Results are cached for an hour, so repeat scans are instant and free.
- Each IP address (or phone number for SMS) can scan 60 links per hour (`SCANS_PER_HOUR_PER_CLIENT`).
- The cache and limits live in memory, so they reset when the server restarts and aren't shared between multiple server processes.

## Verdicts

| Verdict | Meaning |
|---|---|
| Dangerous | Google Safe Browsing or at least one VirusTotal engine flagged it as malicious |
| Suspicious | Flagged as suspicious, domain is under 30 days old, or the URL has strong red flags |
| No threats found | Nothing flagged it. This isn't a guarantee: brand-new phishing pages are often not listed yet |
| Could not verify | VirusTotal was unavailable (e.g. rate limit) and nothing else flagged it |

## Tests

```bash
cd backend
pip install -r requirements-dev.txt
python -m pytest
```

The tests replace VirusTotal, Google, WHOIS and Twilio with fakes, so they need no keys and use no API quota.
