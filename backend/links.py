"""Finding, cleaning and normalizing URLs. Pure functions, no network access."""
import re
from urllib.parse import urlparse

import tldextract

# Matches http(s):// links and bare www. links. `www.` must not follow a letter,
# dot, slash or @, so it isn't matched again inside "https://www.example.com".
_URL_RE = re.compile(
    r"""(?:https?://|(?<![\w./@])www\.)[^\s<>"'{}|\\^`\[\]]+""",
    re.IGNORECASE,
)
_TRAILING_PUNCT = ".,;:!?*'\""

# Use the public suffix list bundled with tldextract instead of downloading it at runtime.
tld_extract = tldextract.TLDExtract(suffix_list_urls=())


def _trim(url):
    """Drop punctuation that ends a sentence rather than the URL, e.g. 'see https://x.com.'"""
    while url:
        if url[-1] in _TRAILING_PUNCT:
            url = url[:-1]
        elif url[-1] == ")" and url.count(")") > url.count("("):
            url = url[:-1]
        else:
            break
    return url


def normalize_url(raw):
    """Return the URL with a scheme (https:// added if missing), or None if it isn't a usable web URL."""
    url = raw.strip()
    if not url:
        return None
    # "javascript:..." or "ftp://..." have a scheme; "example.com:8080/x" is a host and port.
    scheme = re.match(r"^([a-z][a-z0-9+.-]*):(?!\d+(?:[/?#]|$))", url, re.IGNORECASE)
    if scheme is None:
        url = "https://" + url
    elif scheme.group(1).lower() not in ("http", "https"):
        return None
    parsed = urlparse(url)
    try:
        parsed.port  # raises ValueError for a malformed port
    except ValueError:
        return None
    if not parsed.hostname:
        return None
    return url


def extract_urls(text):
    """All distinct URLs in the text, in the order they first appear, each with a scheme."""
    seen = []
    for match in _URL_RE.findall(text):
        url = normalize_url(_trim(match))
        if url and url not in seen:
            seen.append(url)
    return seen


def registered_domain(url):
    """'https://login.secure.example.co.uk/x' -> 'example.co.uk'. None for IP addresses or unknown suffixes."""
    host = urlparse(url).hostname or ""
    return tld_extract(host).top_domain_under_public_suffix or None
