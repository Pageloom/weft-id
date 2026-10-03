"""Tests for CSP source expressions built from stored URLs."""

import pytest
from utils.csp import csp_origin, csp_origins, csp_source

INJECTION = "https://a.example; frame-ancestors *; script-src-elem * 'unsafe-inline';x/logo.png"


@pytest.mark.parametrize(
    ("url", "origin"),
    [
        ("https://rp.example/cb?x=1", "https://rp.example"),
        ("https://rp.example:8443/cb", "https://rp.example:8443"),
        ("http://localhost:3000/callback", "http://localhost:3000"),
        ("http://127.0.0.1:8080/cb", "http://127.0.0.1:8080"),
        ("http://[::1]:8080/cb", "http://[::1]:8080"),
        ("myapp://callback/path", "myapp://callback"),
        ("https://b:8443", "https://b:8443"),
    ],
)
def test_origin_of_a_plain_url(url, origin):
    assert csp_origin(url) == origin
    # Idempotent: an origin is its own origin.
    assert csp_origin(origin) == origin


@pytest.mark.parametrize(
    "url",
    [
        None,
        "",
        INJECTION,
        "https://a.example 'unsafe-inline'/x",
        "https://user:pw@a.example/x",
        "https://a.example:port/x",
        "https://a.example:/x",
        "https://a.example,b.example/x",
        'https://a.example"/x',
        "https://[::1/x",
        "com.example.app:/cb",
        "/relative",
        "not a url",
    ],
)
def test_no_origin_for_anything_else(url):
    assert csp_origin(url) is None
    assert csp_source(url) is None


def test_source_keeps_a_clean_url():
    assert csp_source("https://sp.example/saml/acs") == "https://sp.example/saml/acs"


@pytest.mark.parametrize(
    "url",
    [
        "https://sp.example/acs; script-src *",
        "https://sp.example/acs 'unsafe-inline'",
        "https://sp.example/a,b",
        "https://sp.example/acs\tx",
        # urlsplit drops the newline, so the origin is clean; the URL is not.
        "https://sp.example\n/acs",
    ],
)
def test_source_falls_back_to_the_origin(url):
    assert csp_source(url) == "https://sp.example"


def test_origins_drops_unusable_urls_and_duplicates():
    assert csp_origins(
        ["https://a.example/x", INJECTION, "https://a.example/y", "https://b.example:8443/z"]
    ) == ["https://a.example", "https://b.example:8443"]
    assert csp_origins(None) == []
