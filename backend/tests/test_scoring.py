from scoring import calculate_risk_score, get_verdict, url_warnings

CLEAN_VT = {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 20}


def codes(url):
    return {w["code"] for w in url_warnings(url)}


def test_ordinary_url_has_no_warnings():
    assert codes("https://www.github.com/login") == set()


def test_url_warnings():
    assert "ip_host" in codes("http://45.33.12.9/paypal")
    assert "userinfo" in codes("https://paypal.com@evil.example/")
    assert "punycode" in codes("https://xn--pypal-4ve.com")
    assert "many_subdomains" in codes("https://paypal.com.secure.login.evil.net")
    assert "suspicious_tld" in codes("https://free-prizes.xyz")
    assert "http_login" in codes("http://mybank.com/login")
    assert "http_login" not in codes("https://mybank.com/login")


def test_clean_result():
    assert get_verdict(CLEAN_VT, False, 4000, []) == "clean"
    assert calculate_risk_score(CLEAN_VT, False, 4000, []) == 0


def test_dangerous_when_any_engine_or_google_flags_it():
    assert get_verdict({**CLEAN_VT, "malicious": 1}, False, 4000, []) == "dangerous"
    assert get_verdict(CLEAN_VT, True, 4000, []) == "dangerous"


def test_new_domain_is_suspicious():
    assert get_verdict(CLEAN_VT, False, 5, []) == "suspicious"
    assert calculate_risk_score(CLEAN_VT, False, 5, []) == 20


def test_unknown_domain_age_adds_small_risk():
    assert calculate_risk_score(CLEAN_VT, False, None, []) == 5


def test_strong_url_warning_makes_it_suspicious():
    warnings = url_warnings("http://45.33.12.9/")
    assert get_verdict(CLEAN_VT, False, None, warnings) == "suspicious"


def test_warning_points_are_capped():
    warnings = [{"code": str(i), "message": "", "points": 20} for i in range(5)]
    assert calculate_risk_score(CLEAN_VT, False, 4000, warnings) == 30


def test_unknown_when_virustotal_unavailable():
    assert get_verdict(None, False, 4000, []) == "unknown"
    assert get_verdict(None, True, 4000, []) == "dangerous"


def test_score_never_exceeds_100():
    vt = {"malicious": 20, "suspicious": 20}
    assert calculate_risk_score(vt, True, 1, url_warnings("http://1.2.3.4/login")) == 100
