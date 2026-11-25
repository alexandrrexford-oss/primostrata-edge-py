from __future__ import annotations

import ipaddress
import re
import zlib
from collections import OrderedDict
from dataclasses import dataclass
from typing import Iterable, Tuple
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

MAX_URL_BYTES = 2048
MAX_HEADERS = 64
MAX_HEADER_TOTAL_BYTES = 8192
CACHE_CAP = 4096

_SCRIPT_RE = re.compile(rb"<script\b[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
_SQLI_XSS_TOKENS = (
    "union%20select",
    "union select",
    "union+select",
    "<script",
    "%3cscript",
    "javascript:",
    "onerror=",
    "onload=",
)
_TRAVERSAL_TOKENS = ("..", "%2e", "%5c", "%0d", "%0a", "%00")


class PureEdgeBlockedError(PermissionError):
    pass


class PureEdgeRateLimitedError(RuntimeError):
    pass


@dataclass(slots=True)
class PureEdgeResult:
    cache_hit: bool
    sealed_wire: bytes


def _is_forbidden_ipv4(ip: ipaddress.IPv4Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_reserved
        or ip in ipaddress.IPv4Network("100.64.0.0/10")
    )


def _is_forbidden_ipv6(ip: ipaddress.IPv6Address) -> bool:
    if ip.ipv4_mapped is not None:
        return _is_forbidden_ipv4(ip.ipv4_mapped)
    return (
        ip.is_loopback
        or ip.is_unspecified
        or ip.is_link_local
        or ip.is_private
        or ip.is_multicast
        or ip.is_reserved
    )


def _parse_c_int_auto(s: str) -> int:
    if s.startswith(("0x", "0X")):
        return int(s, 16)
    if s.startswith("0") and len(s) > 1 and s.isdigit():
        return int(s, 8)
    return int(s, 10)


def _parse_obfuscated_ipv4(host: str) -> ipaddress.IPv4Address | None:
    # Fast-fail if it looks like a normal domain with letters outside hex/octal
    try:
        return ipaddress.IPv4Address(host)
    except ValueError:
        pass
    # Handle single integer decimal/hex/octal IPv4 (e.g. 2130706433 or 0x7f000001) or dotted octal/hex
    parts = host.split(".")
    if len(parts) == 1:
        try:
            val = _parse_c_int_auto(host)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            return None
    elif len(parts) == 4:
        try:
            octets = [_parse_c_int_auto(p) for p in parts]
            if all(0 <= o <= 255 for o in octets):
                return ipaddress.IPv4Address(bytes(octets))
        except ValueError:
            return None
    return None


class PurePythonEdge:
    """Full pure-Python equivalent of Primostrata Edge (using stdlib + C-backed zlib & cryptography)."""

    def __init__(self) -> None:
        self._cache: OrderedDict[str, bytes] = OrderedDict()
        self._rate_windows: dict[int, tuple[int, int]] = {}

    def reset(self) -> None:
        self._cache.clear()
        self._rate_windows.clear()

    def inspect(self, url: str, headers: Iterable[Tuple[str, str]] = ()) -> bool:
        if not url or len(url.encode("utf-8", errors="ignore")) > MAX_URL_BYTES:
            return False
        for ch in url:
            o = ord(ch)
            if o < 0x21 or o >= 0x7F or ch == "\\":
                return False
        if not (url.startswith("https://") or url.startswith("http://")):
            return False

        parsed = urlparse(url)
        if not parsed.netloc or "@" in parsed.netloc:
            return False

        raw_host = parsed.hostname or ""
        host_lc = raw_host.rstrip(".").lower()
        if (
            not host_lc
            or host_lc == "localhost"
            or host_lc.endswith((".localhost", ".local", ".internal", ".home.arpa"))
            or "metadata.google" in host_lc
            or host_lc.startswith("xn--")
            or ".xn--" in host_lc
        ):
            return False

        # IPv6 literal check
        if ":" in host_lc:
            try:
                ip6 = ipaddress.IPv6Address(host_lc)
                if _is_forbidden_ipv6(ip6):
                    return False
            except ValueError:
                return False
        else:
            ip4 = _parse_obfuscated_ipv4(host_lc)
            if ip4 is not None and _is_forbidden_ipv4(ip4):
                return False

        url_lc = url.lower()
        for tok in _TRAVERSAL_TOKENS:
            if tok in url_lc:
                return False
        for tok in _SQLI_XSS_TOKENS:
            if tok in url_lc:
                return False

        hdr_list = list(headers)
        if len(hdr_list) > MAX_HEADERS:
            return False
        total_hdr_bytes = 0
        cl_count = 0
        has_te = False
        for k, v in hdr_list:
            total_hdr_bytes += len(k) + len(v)
            if total_hdr_bytes > MAX_HEADER_TOTAL_BYTES or not k:
                return False
            for ch in k:
                o = ord(ch)
                if o <= 0x20 or o >= 0x7F or ch == ":":
                    return False
            if "\r" in v or "\n" in v or "\x00" in v:
                return False
            kl = k.lower()
            if kl == "content-length":
                cl_count += 1
                vt = v.strip()
                if not vt or not vt.isdigit():
                    return False
            elif "transfer-encoding" in kl:
                has_te = True
        if cl_count > 1 or (cl_count >= 1 and has_te):
            return False
        return True

    def strip_scripts(self, html: str | bytes) -> bytes:
        raw = html.encode("utf-8") if isinstance(html, str) else html
        return _SCRIPT_RE.sub(b"", raw)

    def compress(self, data: bytes, level: int = 1) -> bytes:
        return zlib.compress(data, level=level)

    def decompress(self, data: bytes) -> bytes:
        return zlib.decompress(data)

    def seal(self, key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)

    def open(self, key: bytes, nonce: bytes, aad: bytes, wire: bytes) -> bytes:
        return ChaCha20Poly1305(key).decrypt(nonce, wire, aad)

    def handle_request(
        self,
        url: str,
        headers: Iterable[Tuple[str, str]],
        html: str | bytes,
        key: bytes,
        nonce: bytes,
        aad: bytes,
        flow_hash: int = 1,
        epoch_sec: int = 1,
        rate_limit_per_sec: int = 0,
        cacheable: bool = True,
    ) -> PureEdgeResult:
        if not self.inspect(url, headers):
            raise PureEdgeBlockedError("Blocked by PurePython WAF")

        if rate_limit_per_sec > 0:
            prev_ep, cnt = self._rate_windows.get(flow_hash, (epoch_sec, 0))
            if prev_ep != epoch_sec:
                self._rate_windows[flow_hash] = (epoch_sec, 1)
            else:
                cnt += 1
                self._rate_windows[flow_hash] = (epoch_sec, cnt)
                if cnt > rate_limit_per_sec:
                    raise PureEdgeRateLimitedError("Blocked by PurePython rate limiter")

        cache_hit = False
        if cacheable and url in self._cache:
            comp = self._cache[url]
            self._cache.move_to_end(url)
            cache_hit = True
        else:
            clean = self.strip_scripts(html)
            comp = self.compress(clean, level=1)
            if cacheable:
                if len(self._cache) >= CACHE_CAP:
                    self._cache.popitem(last=False)
                self._cache[url] = comp

        sealed = self.seal(key, nonce, aad, comp)
        return PureEdgeResult(cache_hit=cache_hit, sealed_wire=sealed)


class PurePythonEdgeMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, edge: PurePythonEdge | None = None, strip_html_scripts: bool = True):
        super().__init__(app)
        self.edge = edge or PurePythonEdge()
        self.strip_html_scripts = strip_html_scripts

    async def dispatch(self, request: Request, call_next) -> Response:
        if not self.edge.inspect(str(request.url), list(request.headers.items())):
            return JSONResponse({"detail": "Blocked by PurePython WAF"}, status_code=403)
        resp = await call_next(request)
        if (
            self.strip_html_scripts
            and resp.headers.get("content-type", "").startswith("text/html")
        ):
            if hasattr(resp, "body"):
                raw_body = resp.body
            else:
                chunks = [chunk async for chunk in resp.body_iterator]
                raw_body = b"".join(chunks)
            clean = self.edge.strip_scripts(raw_body)
            hdrs = dict(resp.headers)
            hdrs.pop("content-length", None)
            return Response(content=clean, status_code=resp.status_code, headers=hdrs)
        return resp
