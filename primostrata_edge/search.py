from __future__ import annotations

import ctypes
from typing import List, Optional, Sequence, Tuple

from .sdk import OK_ALLOW_OR_HIT, _default_lib_path


def _bind_search_lib(path: str) -> ctypes.CDLL:
    lib = ctypes.CDLL(path)

    lib.primo_search_create.argtypes = []
    lib.primo_search_create.restype = ctypes.c_void_p

    lib.primo_search_add_doc.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint64,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_int32),
    ]
    lib.primo_search_add_doc.restype = ctypes.c_int32

    lib.primo_search_query.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_int32),
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_int64),
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.primo_search_query.restype = ctypes.c_int32

    lib.primo_search_destroy.argtypes = [ctypes.c_void_p]
    lib.primo_search_destroy.restype = None

    return lib


class PrimoSearch:
    """Hybrid ALX-24 exact + cross-script phonetic conduit + VEC31 2-bit ANN search engine."""

    def __init__(self, lib_path: str | None = None, max_k: int = 64) -> None:
        self._lib = _bind_search_lib(lib_path or _default_lib_path())
        self._handle = self._lib.primo_search_create()
        if not self._handle:
            raise MemoryError("Failed to create PrimoSearch handle")
        self._max_k = max_k
        self._out_ids = (ctypes.c_uint64 * max_k)()
        self._out_scores = (ctypes.c_int64 * max_k)()
        self._out_count = ctypes.c_size_t(0)
        self._vec_buf = (ctypes.c_int32 * 64)()

    def close(self) -> None:
        if getattr(self, "_handle", None):
            self._lib.primo_search_destroy(self._handle)
            self._handle = None

    def __enter__(self) -> "PrimoSearch":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def add_doc(
        self, doc_id: int, text: str | bytes, vec64: Optional[Sequence[int]] = None
    ) -> None:
        tb = text.encode("utf-8") if isinstance(text, str) else text
        if vec64 is not None:
            for i in range(64):
                self._vec_buf[i] = int(vec64[i]) if i < len(vec64) else 0
            vp = self._vec_buf
        else:
            vp = None
        rc = self._lib.primo_search_add_doc(self._handle, doc_id, tb, len(tb), vp)
        if rc != OK_ALLOW_OR_HIT:
            raise RuntimeError(f"PrimoSearch add_doc failed rc={rc}")

    def query(
        self,
        text: str | bytes = "",
        top_k: int = 10,
        vec64: Optional[Sequence[int]] = None,
    ) -> List[Tuple[int, int]]:
        if top_k > self._max_k:
            self._max_k = top_k
            self._out_ids = (ctypes.c_uint64 * top_k)()
            self._out_scores = (ctypes.c_int64 * top_k)()
        qb = text.encode("utf-8") if isinstance(text, str) else text
        if vec64 is not None:
            for i in range(64):
                self._vec_buf[i] = int(vec64[i]) if i < len(vec64) else 0
            vp = self._vec_buf
        else:
            vp = None
        rc = self._lib.primo_search_query(
            self._handle,
            qb,
            len(qb),
            vp,
            top_k,
            self._out_ids,
            self._out_scores,
            ctypes.byref(self._out_count),
        )
        if rc != OK_ALLOW_OR_HIT:
            raise RuntimeError(f"PrimoSearch query failed rc={rc}")
        n = int(self._out_count.value)
        return [(int(self._out_ids[i]), int(self._out_scores[i])) for i in range(n)]
