"""API tests with the outside services (VirusTotal, Safe Browsing, WHOIS, Twilio) replaced by fakes."""
import os

os.environ.setdefault("VIRUSTOTAL_API_KEY", "test-key")

import pytest
from fastapi.testclient import TestClient

import main


@pytest.fixture
def client(monkeypatch):
    async def fake_expand(_client, url):
        return url

    async def fake_vt(_client, url):
        return {"malicious": 1 if "evil" in url else 0, "suspicious": 0, "harmless": 60, "undetected": 10}

    async def fake_gsb(_client, _urls):
        return False

    monkeypatch.setattr(main, "VT_KEY", "test-key")
    monkeypatch.setattr(main, "expand_url", fake_expand)
    monkeypatch.setattr(main, "check_virustotal", fake_vt)
    monkeypatch.setattr(main, "check_google_safe_browsing", fake_gsb)
    monkeypatch.setattr(main, "check_domain_age", lambda url: 3000)
    main._cache.clear()
    main._client_hits.clear()
    with TestClient(main.app) as test_client:
        yield test_client


def test_scan_adds_scheme_and_returns_verdict(client):
    data = client.post("/scan", json={"url": "example.com"}).json()
    assert data["url"] == "https://example.com"
    assert data["verdict"] == "clean"
    assert data["errors"] == []


def test_scan_rejects_non_web_address(client):
    assert client.post("/scan", json={"url": "javascript:alert(1)"}).status_code == 422


def test_second_scan_is_cached(client):
    client.post("/scan", json={"url": "https://example.com"})
    assert client.post("/scan", json={"url": "https://example.com"}).json()["cached"] is True


def test_virustotal_failure_still_returns_json(client, monkeypatch):
    async def broken_vt(_client, _url):
        raise main.VirusTotalError("VirusTotal rate limit reached. Try again in a minute.")

    monkeypatch.setattr(main, "check_virustotal", broken_vt)
    response = client.post("/scan", json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.json()["verdict"] == "unknown"
    assert "rate limit" in response.json()["errors"][0]


def test_bulk_marks_invalid_entries(client):
    results = client.post("/scan/bulk", json={"urls": ["https://evil.com", "ftp://x"]}).json()["results"]
    assert [r["verdict"] for r in results] == ["dangerous", "error"]


def test_bulk_rejects_more_than_20(client):
    assert client.post("/scan/bulk", json={"urls": ["https://a.com"] * 21}).status_code == 422


def test_per_client_limit(client, monkeypatch):
    monkeypatch.setattr(main, "SCANS_PER_HOUR_PER_CLIENT", 2)
    assert client.post("/scan", json={"url": "https://a.com"}).status_code == 200
    assert client.post("/scan", json={"url": "https://b.com"}).status_code == 200
    assert client.post("/scan", json={"url": "https://c.com"}).status_code == 429


def test_extract_links(client):
    data = client.post("/extract-links", json={"text": "Click https://evil.com. or www.x.org"}).json()
    assert data["urls"] == ["https://evil.com", "https://www.x.org"]


def test_sms_rejects_unsigned_requests(client, monkeypatch):
    monkeypatch.setattr(main, "TWILIO_SID", "AC123")
    monkeypatch.setattr(main, "TWILIO_TOKEN", "secret")
    monkeypatch.setattr(main, "TWILIO_NUMBER", "+15550000000")
    response = client.post("/sms", data={"Body": "https://evil.com", "From": "+15551112222"})
    assert response.status_code == 403


def test_sms_replies_immediately_and_texts_results(client, monkeypatch):
    from twilio.request_validator import RequestValidator

    monkeypatch.setattr(main, "TWILIO_SID", "AC123")
    monkeypatch.setattr(main, "TWILIO_TOKEN", "secret")
    monkeypatch.setattr(main, "TWILIO_NUMBER", "+15550000000")
    sent = []

    class FakeMessages:
        def create(self, **kwargs):
            sent.append(kwargs)

    class FakeTwilio:
        def __init__(self, *_args):
            self.messages = FakeMessages()

    monkeypatch.setattr(main, "TwilioClient", FakeTwilio)
    form = {"Body": "Is https://evil.com safe?", "From": "+15551112222"}
    signature = RequestValidator("secret").compute_signature("http://testserver/sms", form)
    response = client.post("/sms", data=form, headers={"X-Twilio-Signature": signature})

    assert response.status_code == 200
    assert "Scanning 1 link" in response.text
    assert sent and sent[0]["to"] == "+15551112222"
    assert "DANGEROUS" in sent[0]["body"]
