from links import extract_urls, normalize_url, registered_domain


def test_trailing_punctuation_is_dropped():
    text = "Visit https://evil.com. Or (https://evil.org/path) now!"
    assert extract_urls(text) == ["https://evil.com", "https://evil.org/path"]


def test_balanced_parentheses_are_kept():
    assert extract_urls("see https://en.wikipedia.org/wiki/Foo_(bar)") == ["https://en.wikipedia.org/wiki/Foo_(bar)"]


def test_www_links_without_scheme_are_found():
    assert extract_urls("go to www.example.com/login, quickly") == ["https://www.example.com/login"]


def test_www_inside_full_url_is_not_duplicated():
    assert extract_urls("https://www.example.com") == ["https://www.example.com"]


def test_order_preserved_and_duplicates_removed():
    text = "https://b.com https://a.com https://b.com"
    assert extract_urls(text) == ["https://b.com", "https://a.com"]


def test_html_href_quotes_not_included():
    assert extract_urls('<a href="https://x.com/a">click</a> <a href=\'https://y.com\'>') == [
        "https://x.com/a",
        "https://y.com",
    ]


def test_normalize_url():
    assert normalize_url("example.com") == "https://example.com"
    assert normalize_url("  http://example.com/x ") == "http://example.com/x"
    assert normalize_url("ftp://example.com") is None
    assert normalize_url("javascript:alert(1)") is None
    assert normalize_url("") is None
    assert normalize_url("example.com:8080/x") == "https://example.com:8080/x"
    assert normalize_url("mailto:a@b.com") is None


def test_registered_domain():
    assert registered_domain("https://login.secure.example.co.uk/x") == "example.co.uk"
    assert registered_domain("https://www.google.com") == "google.com"
    assert registered_domain("http://192.168.1.1/") is None
