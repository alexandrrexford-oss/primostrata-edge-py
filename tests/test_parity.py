import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from primostrata_edge import EdgeBlockedError, EdgeRateLimitedError, PrimostrataEdge
from primostrata_edge.middleware import PrimostrataEdgeMiddleware
from pure_python_edge import (
    PureEdgeBlockedError,
    PureEdgeRateLimitedError,
    PurePythonEdge,
    PurePythonEdgeMiddleware,
)

KEY = b"\x42" * 32
NONCE = b"\x11" * 12
AAD = b"edge.primostrata.org"
HTML = (
    b"<html><body><h1>Product</h1><script>alert('xss')</script>"
    b"<p>Fast shipping and verified checkout.</p><SCRIPT src='evil.js'></SCRIPT></body></html>"
)


def test_security_parity_all_vectors():
    primo = PrimostrataEdge()
    pure = PurePythonEdge()

    honest_cases = [
        ("https://edge.primostrata.org/api/v1/items?page=2", [("Host", "edge.primostrata.org")]),
        ("https://shop.example.kz/catalog/shoes", [("Accept-Encoding", "gzip, zin")]),
    ]
    for url, hdrs in honest_cases:
        assert primo.inspect(url, hdrs) is True
        assert pure.inspect(url, hdrs) is True

    attack_cases = [
        # SSRF variants
        ("http://169.254.169.254/latest/meta-data/", []),
        ("http://127.0.0.1:8080/admin", []),
        ("http://[::1]/internal", []),
        ("http://[::ffff:127.0.0.1]/admin", []),
        ("http://2130706433/secret", []),
        ("http://0x7f000001/secret", []),
        ("http://0177.0.0.1/secret", []),
        ("http://localhost:9000/metrics", []),
        ("http://user@example.com/", []),
        ("https://evil.internal/keys", []),
        # Traversal & CRLF
        ("https://example.com/static/../../etc/passwd", []),
        ("https://example.com/static/%2e%2e/secret", []),
        ("https://example.com/api?q=a%0d%0aSet-Cookie:x=1", []),
        # SQLi & XSS
        ("https://example.com/search?q=1+union%20select+password", []),
        ("https://example.com/search?q=<script>alert(1)</script>", []),
        # HTTP Request Smuggling
        (
            "https://example.com/api",
            [("Content-Length", "10"), ("Transfer-Encoding", "chunked")],
        ),
        (
            "https://example.com/api",
            [("Content-Length", "10"), ("Content-Length", "20")],
        ),
    ]
    for url, hdrs in attack_cases:
        assert primo.inspect(url, hdrs) is False, f"Primo missed {url}"
        assert pure.inspect(url, hdrs) is False, f"Pure missed {url}"


def test_full_pipeline_roundtrip_and_tamper_parity():
    with PrimostrataEdge() as primo:
        pure = PurePythonEdge()

        r1 = primo.handle_request("https://edge.primostrata.org/p/1", [("Host", "edge.primostrata.org")], HTML, KEY, NONCE, AAD, cacheable=True)
        r2 = primo.handle_request("https://edge.primostrata.org/p/1", [("Host", "edge.primostrata.org")], HTML, KEY, NONCE, AAD, cacheable=True)
        assert r1.cache_hit is False
        assert r2.cache_hit is True
        assert r1.sealed_wire == r2.sealed_wire

        p1 = pure.handle_request("https://edge.primostrata.org/p/1", [("Host", "edge.primostrata.org")], HTML, KEY, NONCE, AAD, cacheable=True)
        p2 = pure.handle_request("https://edge.primostrata.org/p/1", [("Host", "edge.primostrata.org")], HTML, KEY, NONCE, AAD, cacheable=True)
        assert p1.cache_hit is False
        assert p2.cache_hit is True

        # Verify bit-exact decryption + decompression + script removal
        dec_primo = primo.decompress(primo.open(KEY, NONCE, AAD, r1.sealed_wire))
        dec_pure = pure.decompress(pure.open(KEY, NONCE, AAD, p1.sealed_wire))
        assert dec_primo == dec_pure
        assert b"<script" not in dec_primo.lower()
        assert b"Fast shipping" in dec_primo

        # Tamper rejection
        bad = bytearray(r1.sealed_wire)
        bad[-1] ^= 0xFF
        with pytest.raises(ValueError):
            primo.open(KEY, NONCE, AAD, bytes(bad))

        # Rate limiter parity
        for i in range(3):
            primo.handle_request("https://edge.primostrata.org/dyn", [], HTML, KEY, NONCE, AAD, flow_hash=99, epoch_sec=10, rate_limit_per_sec=3, cacheable=False)
            pure.handle_request("https://edge.primostrata.org/dyn", [], HTML, KEY, NONCE, AAD, flow_hash=99, epoch_sec=10, rate_limit_per_sec=3, cacheable=False)
        with pytest.raises(EdgeRateLimitedError):
            primo.handle_request("https://edge.primostrata.org/dyn", [], HTML, KEY, NONCE, AAD, flow_hash=99, epoch_sec=10, rate_limit_per_sec=3, cacheable=False)
        with pytest.raises(PureEdgeRateLimitedError):
            pure.handle_request("https://edge.primostrata.org/dyn", [], HTML, KEY, NONCE, AAD, flow_hash=99, epoch_sec=10, rate_limit_per_sec=3, cacheable=False)

        with pytest.raises(EdgeBlockedError):
            primo.handle_request("http://169.254.169.254/latest", [], HTML, KEY, NONCE, AAD)
        with pytest.raises(PureEdgeBlockedError):
            pure.handle_request("http://169.254.169.254/latest", [], HTML, KEY, NONCE, AAD)


def test_fastapi_middleware_parity():
    def build_app(mw_cls):
        app = FastAPI()
        app.add_middleware(mw_cls)

        @app.get("/ok")
        def ok():
            return HTMLResponse("<div>hello<script>evil()</script></div>")

        return TestClient(app)

    c_primo = build_app(PrimostrataEdgeMiddleware)
    c_pure = build_app(PurePythonEdgeMiddleware)

    for c in (c_primo, c_pure):
        r = c.get("/ok")
        assert r.status_code == 200
        assert r.text == "<div>hello</div>"
        blk = c.get("/ok?q=<script>alert(1)</script>")
        assert blk.status_code == 403
