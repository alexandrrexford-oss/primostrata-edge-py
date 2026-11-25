from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from typing import Iterable, Tuple

OK_ALLOW_OR_HIT = 0
OK_PROCESSED_MISS = 1
ERR_INVALID_ARGS = -1
ERR_BUFFER_TOO_SMALL = -2
ERR_BLOCKED_SECURITY = -3
ERR_CODEC_OR_CRYPTO = -4
ERR_RATE_LIMITED = -5


class EdgeBlockedError(PermissionError):
    """Raised when L4/L7 SHIELD rejects SSRF, smuggling, traversal, or XSS/SQLi."""


class EdgeRateLimitedError(RuntimeError):
    """Raised when a flow exceeds its per-second rate quota."""


@dataclass(slots=True)
class EdgeResult:
    cache_hit: bool
    sealed_wire: bytes


def _default_lib_path() -> str:
    env_path = os.environ.get("PRIMOSTRATA_EDGE_LIB")
    if env_path and os.path.isfile(env_path):
        return env_path
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "primostrata_edge.dll"),
        os.path.join(here, "libprimostrata_edge.so"),
        os.path.abspath(
            os.path.join(here, "..", "rust_ffi", "target", "release", "primostrata_edge.dll")
        ),
        os.path.abspath(
            os.path.join(here, "..", "rust_ffi", "target", "release", "libprimostrata_edge.so")
        ),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    raise FileNotFoundError(
        "Compiled Primostrata Edge binary not found. Expected primostrata_edge.dll / .so"
    )


def _load_cdylib(path: str) -> ctypes.CDLL:
    lib = ctypes.CDLL(path)

    lib.primo_edge_create.argtypes = []
    lib.primo_edge_create.restype = ctypes.c_void_p

    lib.primo_edge_destroy.argtypes = [ctypes.c_void_p]
    lib.primo_edge_destroy.restype = None

    lib.primo_edge_reset.argtypes = [ctypes.c_void_p]
    lib.primo_edge_reset.restype = ctypes.c_int32

    lib.primo_edge_inspect.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    lib.primo_edge_inspect.restype = ctypes.c_int32

    lib.primo_edge_strip_scripts.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.primo_edge_strip_scripts.restype = ctypes.c_int32

    lib.primo_edge_compress_zin.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_uint8,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.primo_edge_compress_zin.restype = ctypes.c_int32

    lib.primo_edge_decompress_zin.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.primo_edge_decompress_zin.restype = ctypes.c_int32

    lib.primo_edge_seal_aead.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.primo_edge_seal_aead.restype = ctypes.c_int32

    lib.primo_edge_open_aead.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.primo_edge_open_aead.restype = ctypes.c_int32

    lib.primo_edge_process_request.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_uint64,
        ctypes.c_uint32,
        ctypes.c_uint8,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.primo_edge_process_request.restype = ctypes.c_int32

    return lib


def encode_headers_tsv(headers: Iterable[Tuple[str, str]]) -> bytes:
    parts = [f"{k}\t{v}" for k, v in headers]
    return "\n".join(parts).encode("utf-8", errors="surrogateescape")


class PrimostrataEdge:
    """Python SDK backed by compiled Primostrata Edge binary (`SHIELD` + `ZIN` + `STORE64` + `AEAD`)."""

    def __init__(self, lib_path: str | None = None, buf_bytes: int = 262_144) -> None:
        self._lib = _load_cdylib(lib_path or _default_lib_path())
        self._handle = self._lib.primo_edge_create()
        if not self._handle:
            raise MemoryError("Failed to allocate PrimostrataEdge native state")
        self._buf_cap = buf_bytes
        self._out_buf = ctypes.create_string_buffer(buf_bytes)
        self._out_len = ctypes.c_size_t(0)

    def close(self) -> None:
        if getattr(self, "_handle", None):
            self._lib.primo_edge_destroy(self._handle)
            self._handle = None

    def __del__(self) -> None:
        self.close()

    def __enter__(self) -> "PrimostrataEdge":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def reset(self) -> None:
        rc = self._lib.primo_edge_reset(self._handle)
        if rc != 0:
            raise RuntimeError(f"reset failed with rc={rc}")

    def _ensure_cap(self, needed: int) -> None:
        if needed > self._buf_cap:
            self._buf_cap = max(needed, self._buf_cap * 2)
            self._out_buf = ctypes.create_string_buffer(self._buf_cap)

    def inspect(self, url: str | bytes, headers: Iterable[Tuple[str, str]] | bytes = ()) -> bool:
        url_b = url.encode("utf-8", errors="surrogateescape") if isinstance(url, str) else url
        hdr_b = headers if isinstance(headers, (bytes, bytearray)) else encode_headers_tsv(headers)
        rc = self._lib.primo_edge_inspect(url_b, len(url_b), hdr_b, len(hdr_b))
        return rc == OK_ALLOW_OR_HIT

    def strip_scripts(self, html: str | bytes) -> bytes:
        html_b = html.encode("utf-8") if isinstance(html, str) else html
        rc = self._lib.primo_edge_strip_scripts(
            html_b, len(html_b), self._out_buf, self._buf_cap, ctypes.byref(self._out_len)
        )
        if rc == ERR_BUFFER_TOO_SMALL:
            self._ensure_cap(self._out_len.value)
            rc = self._lib.primo_edge_strip_scripts(
                html_b, len(html_b), self._out_buf, self._buf_cap, ctypes.byref(self._out_len)
            )
        if rc != OK_ALLOW_OR_HIT:
            raise RuntimeError(f"strip_scripts failed rc={rc}")
        return ctypes.string_at(self._out_buf, self._out_len.value)

    def compress(self, data: bytes, level: int = 1) -> bytes:
        rc = self._lib.primo_edge_compress_zin(
            self._handle,
            data,
            len(data),
            level,
            self._out_buf,
            self._buf_cap,
            ctypes.byref(self._out_len),
        )
        if rc == ERR_BUFFER_TOO_SMALL:
            self._ensure_cap(self._out_len.value)
            rc = self._lib.primo_edge_compress_zin(
                self._handle,
                data,
                len(data),
                level,
                self._out_buf,
                self._buf_cap,
                ctypes.byref(self._out_len),
            )
        if rc != OK_ALLOW_OR_HIT:
            raise RuntimeError(f"compress failed rc={rc}")
        return ctypes.string_at(self._out_buf, self._out_len.value)

    def decompress(self, data: bytes) -> bytes:
        rc = self._lib.primo_edge_decompress_zin(
            data, len(data), self._out_buf, self._buf_cap, ctypes.byref(self._out_len)
        )
        if rc == ERR_BUFFER_TOO_SMALL:
            self._ensure_cap(self._out_len.value)
            rc = self._lib.primo_edge_decompress_zin(
                data, len(data), self._out_buf, self._buf_cap, ctypes.byref(self._out_len)
            )
        if rc != OK_ALLOW_OR_HIT:
            raise RuntimeError(f"decompress failed rc={rc}")
        return ctypes.string_at(self._out_buf, self._out_len.value)

    def seal(self, key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
        if len(key) != 32 or len(nonce) != 12:
            raise ValueError("key must be 32 bytes and nonce must be 12 bytes")
        rc = self._lib.primo_edge_seal_aead(
            key,
            nonce,
            aad,
            len(aad),
            plaintext,
            len(plaintext),
            self._out_buf,
            self._buf_cap,
            ctypes.byref(self._out_len),
        )
        if rc == ERR_BUFFER_TOO_SMALL:
            self._ensure_cap(self._out_len.value)
            rc = self._lib.primo_edge_seal_aead(
                key,
                nonce,
                aad,
                len(aad),
                plaintext,
                len(plaintext),
                self._out_buf,
                self._buf_cap,
                ctypes.byref(self._out_len),
            )
        if rc != OK_ALLOW_OR_HIT:
            raise RuntimeError(f"seal failed rc={rc}")
        return ctypes.string_at(self._out_buf, self._out_len.value)

    def open(self, key: bytes, nonce: bytes, aad: bytes, wire: bytes) -> bytes:
        if len(key) != 32 or len(nonce) != 12:
            raise ValueError("key must be 32 bytes and nonce must be 12 bytes")
        rc = self._lib.primo_edge_open_aead(
            key,
            nonce,
            aad,
            len(aad),
            wire,
            len(wire),
            self._out_buf,
            self._buf_cap,
            ctypes.byref(self._out_len),
        )
        if rc == ERR_BUFFER_TOO_SMALL:
            self._ensure_cap(self._out_len.value)
            rc = self._lib.primo_edge_open_aead(
                key,
                nonce,
                aad,
                len(aad),
                wire,
                len(wire),
                self._out_buf,
                self._buf_cap,
                ctypes.byref(self._out_len),
            )
        if rc != OK_ALLOW_OR_HIT:
            raise ValueError(f"AEAD authentication failed rc={rc}")
        return ctypes.string_at(self._out_buf, self._out_len.value)

    def handle_request(
        self,
        url: str | bytes,
        headers: Iterable[Tuple[str, str]] | bytes,
        html: str | bytes,
        key: bytes,
        nonce: bytes,
        aad: bytes,
        flow_hash: int = 1,
        epoch_sec: int = 1,
        rate_limit_per_sec: int = 0,
        cacheable: bool = True,
    ) -> EdgeResult:
        url_b = url.encode("utf-8", errors="surrogateescape") if isinstance(url, str) else url
        hdr_b = headers if isinstance(headers, (bytes, bytearray)) else encode_headers_tsv(headers)
        html_b = html.encode("utf-8") if isinstance(html, str) else html

        rc = self._lib.primo_edge_process_request(
            self._handle,
            url_b,
            len(url_b),
            hdr_b,
            len(hdr_b),
            html_b,
            len(html_b),
            key,
            nonce,
            aad,
            len(aad),
            flow_hash,
            epoch_sec,
            rate_limit_per_sec,
            1 if cacheable else 0,
            self._out_buf,
            self._buf_cap,
            ctypes.byref(self._out_len),
        )
        if rc == ERR_BUFFER_TOO_SMALL:
            self._ensure_cap(self._out_len.value)
            rc = self._lib.primo_edge_process_request(
                self._handle,
                url_b,
                len(url_b),
                hdr_b,
                len(hdr_b),
                html_b,
                len(html_b),
                key,
                nonce,
                aad,
                len(aad),
                flow_hash,
                epoch_sec,
                rate_limit_per_sec,
                1 if cacheable else 0,
                self._out_buf,
                self._buf_cap,
                ctypes.byref(self._out_len),
            )
        if rc == ERR_BLOCKED_SECURITY:
            raise EdgeBlockedError("Blocked by Primostrata SHIELD L4/L7")
        if rc == ERR_RATE_LIMITED:
            raise EdgeRateLimitedError("Blocked by Primostrata Edge rate limiter")
        if rc not in (OK_ALLOW_OR_HIT, OK_PROCESSED_MISS):
            raise RuntimeError(f"handle_request failed rc={rc}")

        return EdgeResult(
            cache_hit=(rc == OK_ALLOW_OR_HIT),
            sealed_wire=ctypes.string_at(self._out_buf, self._out_len.value),
        )
