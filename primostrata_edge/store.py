from __future__ import annotations

import ctypes
from typing import Optional

from .sdk import ERR_BUFFER_TOO_SMALL, OK_ALLOW_OR_HIT, _default_lib_path

ERR_NOT_FOUND = -6
ERR_INSUFFICIENT = -7
ERR_IO = -8


def _bind_store_lib(path: str) -> ctypes.CDLL:
    lib = ctypes.CDLL(path)

    lib.primo_store_open.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint8]
    lib.primo_store_open.restype = ctypes.c_void_p

    lib.primo_store_put.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    lib.primo_store_put.restype = ctypes.c_int32

    lib.primo_store_get.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.primo_store_get.restype = ctypes.c_int32

    lib.primo_store_decr_if_ge.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_int64,
        ctypes.c_int64,
        ctypes.POINTER(ctypes.c_int64),
    ]
    lib.primo_store_decr_if_ge.restype = ctypes.c_int32

    lib.primo_store_get_counter.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_int64),
    ]
    lib.primo_store_get_counter.restype = ctypes.c_int32

    lib.primo_store_flush.argtypes = [ctypes.c_void_p]
    lib.primo_store_flush.restype = ctypes.c_int32

    lib.primo_store_stats.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64),
    ]
    lib.primo_store_stats.restype = ctypes.c_int32

    lib.primo_store_close.argtypes = [ctypes.c_void_p]
    lib.primo_store_close.restype = None

    return lib


class PrimoStore:
    """Crash-safe `CubePoint64` WAL-KV & atomic inventory DB backed by compiled Rust core."""

    def __init__(
        self,
        path: str = "",
        durable_sync: bool = False,
        lib_path: str | None = None,
        buf_bytes: int = 65_536,
    ) -> None:
        self._lib = _bind_store_lib(lib_path or _default_lib_path())
        pb = path.encode("utf-8") if path else b""
        self._handle = self._lib.primo_store_open(pb, len(pb), 1 if durable_sync else 0)
        if not self._handle:
            raise OSError(f"Failed to open PrimoStore at {path!r}")
        self._buf_cap = buf_bytes
        self._out_buf = ctypes.create_string_buffer(buf_bytes)
        self._out_len = ctypes.c_size_t(0)
        self._rem_i64 = ctypes.c_int64(0)

    def close(self) -> None:
        if getattr(self, "_handle", None):
            self._lib.primo_store_close(self._handle)
            self._handle = None

    def __enter__(self) -> "PrimoStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def put(self, key: str | bytes, val: str | bytes) -> None:
        kb = key.encode("utf-8") if isinstance(key, str) else key
        vb = val.encode("utf-8") if isinstance(val, str) else val
        rc = self._lib.primo_store_put(self._handle, kb, len(kb), vb, len(vb))
        if rc != OK_ALLOW_OR_HIT:
            raise RuntimeError(f"PrimoStore put failed rc={rc}")

    def get(self, key: str | bytes) -> Optional[bytes]:
        kb = key.encode("utf-8") if isinstance(key, str) else key
        rc = self._lib.primo_store_get(
            self._handle, kb, len(kb), self._out_buf, self._buf_cap, ctypes.byref(self._out_len)
        )
        if rc == ERR_NOT_FOUND:
            return None
        if rc == ERR_BUFFER_TOO_SMALL:
            need = self._out_len.value
            self._buf_cap = max(need, self._buf_cap * 2)
            self._out_buf = ctypes.create_string_buffer(self._buf_cap)
            rc = self._lib.primo_store_get(
                self._handle, kb, len(kb), self._out_buf, self._buf_cap, ctypes.byref(self._out_len)
            )
        if rc != OK_ALLOW_OR_HIT:
            raise RuntimeError(f"PrimoStore get failed rc={rc}")
        return ctypes.string_at(self._out_buf, self._out_len.value)

    def decr_if_ge(
        self, key: str | bytes, qty: int, init_if_missing: int = 0
    ) -> tuple[bool, int]:
        kb = key.encode("utf-8") if isinstance(key, str) else key
        rc = self._lib.primo_store_decr_if_ge(
            self._handle, kb, len(kb), qty, init_if_missing, ctypes.byref(self._rem_i64)
        )
        if rc == OK_ALLOW_OR_HIT:
            return True, int(self._rem_i64.value)
        if rc == ERR_INSUFFICIENT:
            return False, int(self._rem_i64.value)
        raise RuntimeError(f"PrimoStore decr_if_ge failed rc={rc}")

    def get_counter(self, key: str | bytes) -> Optional[int]:
        kb = key.encode("utf-8") if isinstance(key, str) else key
        rc = self._lib.primo_store_get_counter(
            self._handle, kb, len(kb), ctypes.byref(self._rem_i64)
        )
        if rc == ERR_NOT_FOUND:
            return None
        if rc != OK_ALLOW_OR_HIT:
            raise RuntimeError(f"PrimoStore get_counter failed rc={rc}")
        return int(self._rem_i64.value)

    def flush(self) -> None:
        rc = self._lib.primo_store_flush(self._handle)
        if rc != OK_ALLOW_OR_HIT:
            raise OSError(f"PrimoStore flush failed rc={rc}")

    def stats(self) -> tuple[int, int]:
        seq = ctypes.c_uint64(0)
        rec = ctypes.c_uint64(0)
        self._lib.primo_store_stats(self._handle, ctypes.byref(seq), ctypes.byref(rec))
        return int(seq.value), int(rec.value)
