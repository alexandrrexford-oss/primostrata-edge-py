from __future__ import annotations

import asyncio
import ctypes
import dis
import inspect
import json
import socket
import struct
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Iterator, Optional, Tuple, get_type_hints
from urllib.parse import parse_qsl

try:
    import orjson as _orjson

    def _json_dumps_bytes(obj: Any) -> bytes:
        return _orjson.dumps(obj)

    def _json_loads_bytes(raw: bytes) -> Any:
        return _orjson.loads(raw)
except ImportError:

    def _json_dumps_bytes(obj: Any) -> bytes:
        return json.dumps(obj, separators=(",", ":")).encode("utf-8")

    def _json_loads_bytes(raw: bytes) -> Any:
        return json.loads(raw)


from .sdk import ERR_BUFFER_TOO_SMALL, OK_ALLOW_OR_HIT, PrimostrataEdge, _default_lib_path

_PRM1_MAGIC = b"PRM1"
_PRM1_HDR = struct.Struct("<4sBBHI")
_PRM1_RESP_HDR = struct.Struct("<4sHBBI")
_ASYNC_OPS = frozenset({"GET_AWAITABLE", "GET_ANEXT", "BEFORE_ASYNC_WITH"})

_DYN_CALLBACK_TYPE = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint16),
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
)


def _bind_server_cdylib(path: str) -> ctypes.CDLL:
    lib = ctypes.CDLL(path)

    lib.primo_server_create.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_uint16,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint16),
    ]
    lib.primo_server_create.restype = ctypes.c_void_p

    lib.primo_server_set_rate_limit.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    lib.primo_server_set_rate_limit.restype = ctypes.c_int32

    lib.primo_server_set_edge_gate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint8]
    lib.primo_server_set_edge_gate.restype = ctypes.c_int32

    lib.primo_server_add_static_route.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_uint16,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_uint8,
    ]
    lib.primo_server_add_static_route.restype = ctypes.c_int32

    lib.primo_server_add_dynamic_route.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_uint8,
        ctypes.c_uint8,
    ]
    lib.primo_server_add_dynamic_route.restype = ctypes.c_int32

    lib.primo_server_start.argtypes = [ctypes.c_void_p, _DYN_CALLBACK_TYPE, ctypes.c_void_p]
    lib.primo_server_start.restype = ctypes.c_int32

    lib.primo_server_stop.argtypes = [ctypes.c_void_p]
    lib.primo_server_stop.restype = ctypes.c_int32

    lib.primo_server_destroy.argtypes = [ctypes.c_void_p]
    lib.primo_server_destroy.restype = None

    return lib


def _cast_value(raw: str, tp: Any) -> Any:
    if tp is int:
        return int(raw)
    if tp is float:
        return float(raw)
    if tp is bool:
        low = raw.lower()
        if low in ("1", "true", "yes", "on"):
            return True
        if low in ("0", "false", "no", "off"):
            return False
        raise ValueError(f"Invalid boolean: {raw!r}")
    return raw


@dataclass(slots=True)
class PrimostrataRequest:
    method: str
    path: str
    query: str
    params: Dict[str, str]
    headers: Dict[str, str]
    body: bytes

    def json(self) -> Any:
        return _json_loads_bytes(self.body)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class PrimostrataResponse:
    __slots__ = ("body_bytes", "status_code", "content_type_bytes")

    def __init__(
        self,
        content: Any,
        status_code: int = 200,
        content_type: str | None = None,
    ) -> None:
        self.status_code = status_code
        if isinstance(content, (bytes, bytearray)):
            self.body_bytes = bytes(content)
            ct = content_type or "application/octet-stream"
        elif isinstance(content, str):
            self.body_bytes = content.encode("utf-8")
            ct = content_type or (
                "text/html; charset=utf-8"
                if content.lstrip().startswith("<")
                else "text/plain; charset=utf-8"
            )
        else:
            self.body_bytes = _json_dumps_bytes(content)
            ct = content_type or "application/json"
        self.content_type_bytes = ct.encode("utf-8")


def _coerce_response(res: Any) -> Tuple[int, bytes, bytes]:
    if isinstance(res, PrimostrataResponse):
        return res.status_code, res.content_type_bytes, res.body_bytes
    if isinstance(res, (dict, list)):
        return 200, b"application/json", _json_dumps_bytes(res)
    if isinstance(res, str):
        ct = b"text/html; charset=utf-8" if res.lstrip().startswith("<") else b"text/plain; charset=utf-8"
        return 200, ct, res.encode("utf-8")
    if isinstance(res, (bytes, bytearray)):
        return 200, b"application/octet-stream", bytes(res)
    return 200, b"application/json", _json_dumps_bytes(res)


@dataclass(slots=True)
class _ParamSpec:
    name: str
    annotation: Any
    has_default: bool
    default: Any
    in_path: bool


@dataclass(slots=True)
class _DynEntry:
    route_id: int
    method: str
    pattern: str
    fn: Callable[..., Any]
    is_coro: bool
    needs_event_loop: bool
    takes_request: bool
    body_param_name: Optional[str]
    param_specs: Tuple[_ParamSpec, ...]
    cacheable: bool
    strip_scripts: bool


@dataclass(slots=True)
class _StaticEntry:
    method: str
    path: str
    status_code: int
    content_type: bytes
    body: bytes
    strip_scripts: bool


class PrimostrataApp:
    """High-performance Python web framework backed by compiled Primostrata Edge binary
    (`REG 0.7 AFG7` async reactor + `SHIELD` L4/L7 + `EdgeGate` + `STORE64` cache + `ZIN` + `PRM1`).
    """

    def __init__(
        self,
        title: str = "Primostrata Edge API",
        version: str = "1.0.0",
        rate_limit_per_sec: int = 0,
        workers: int = 4,
        edge_gate_secret: bytes | None = None,
        docs: bool = True,
        lib_path: str | None = None,
    ) -> None:
        self._lib = _bind_server_cdylib(lib_path or _default_lib_path())
        self.title = title
        self.version = version
        self._rate_limit_per_sec = rate_limit_per_sec
        self._workers = workers
        if edge_gate_secret is not None and len(edge_gate_secret) != 32:
            raise ValueError("edge_gate_secret must be exactly 32 bytes")
        self._edge_gate_secret = edge_gate_secret
        self._docs = docs
        self._static_routes: list[_StaticEntry] = []
        self._dyn_routes: Dict[int, _DynEntry] = {}
        self._middlewares: list[Callable[[PrimostrataRequest, Callable[..., Any]], Any]] = []
        self._next_id = 1
        self._srv_handle: Optional[int] = None
        self._cb_ref: Optional[Any] = None
        self._async_loop: Optional[asyncio.AbstractEventLoop] = None
        self._async_thread: Optional[threading.Thread] = None
        self.port: int = 0
        self.host: str = "127.0.0.1"

    def _ensure_async_loop(self) -> asyncio.AbstractEventLoop:
        if self._async_loop is not None and self._async_loop.is_running():
            return self._async_loop
        ready = threading.Event()
        holder: Dict[str, asyncio.AbstractEventLoop] = {}

        def _runner() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            holder["loop"] = loop
            ready.set()
            loop.run_forever()
            loop.close()

        t = threading.Thread(target=_runner, name="primostrata-asyncio", daemon=True)
        t.start()
        ready.wait(timeout=5.0)
        self._async_thread = t
        self._async_loop = holder["loop"]
        return self._async_loop

    def middleware(self, fn: Callable[[PrimostrataRequest, Callable[..., Any]], Any]) -> Callable[..., Any]:
        self._middlewares.append(fn)
        return fn

    def static(
        self,
        path: str,
        content: Any,
        status_code: int = 200,
        content_type: str | None = None,
        method: str = "GET",
        strip_scripts: bool = True,
    ) -> None:
        """Register a zero-GIL route served directly from Rust memory."""
        st, ct_b, body_b = _coerce_response(PrimostrataResponse(content, status_code, content_type))
        self._static_routes.append(
            _StaticEntry(
                method=method.upper(),
                path=path,
                status_code=st,
                content_type=ct_b,
                body=body_b,
                strip_scripts=strip_scripts,
            )
        )

    def route(
        self,
        path: str,
        methods: Iterable[str] = ("GET",),
        cacheable: bool = False,
        strip_scripts: bool = True,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            is_coro = inspect.iscoroutinefunction(fn)
            needs_loop = False
            if is_coro:
                needs_loop = any(ins.opname in _ASYNC_OPS for ins in dis.get_instructions(fn))

            sig = inspect.signature(fn)
            try:
                hints = get_type_hints(fn)
            except Exception:
                hints = {}

            path_names = set()
            for part in path.split("/"):
                if part.startswith("{") and part.endswith("}") and len(part) > 2:
                    path_names.add(part[1:-1])

            params = [
                p
                for p in sig.parameters.values()
                if p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
            ]
            takes_req = any(p.name in ("req", "request") for p in params) or (
                len(params) == 1 and hints.get(params[0].name, params[0].annotation) is PrimostrataRequest
            )
            body_param = None
            specs: list[_ParamSpec] = []
            for p in params:
                ann = hints.get(p.name, p.annotation)
                if p.name in ("body", "payload") and p.name not in path_names:
                    body_param = p.name
                    continue
                specs.append(
                    _ParamSpec(
                        name=p.name,
                        annotation=str if ann is inspect.Parameter.empty else ann,
                        has_default=p.default is not inspect.Parameter.empty,
                        default=None if p.default is inspect.Parameter.empty else p.default,
                        in_path=(p.name in path_names),
                    )
                )

            for m in methods:
                rid = self._next_id
                self._next_id += 1
                self._dyn_routes[rid] = _DynEntry(
                    route_id=rid,
                    method=m.upper(),
                    pattern=path,
                    fn=fn,
                    is_coro=is_coro,
                    needs_event_loop=needs_loop,
                    takes_request=takes_req,
                    body_param_name=body_param,
                    param_specs=tuple(specs),
                    cacheable=cacheable,
                    strip_scripts=strip_scripts,
                )
            return fn

        return decorator

    def get(
        self, path: str, cacheable: bool = False, strip_scripts: bool = True
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self.route(path, methods=("GET",), cacheable=cacheable, strip_scripts=strip_scripts)

    def post(
        self, path: str, cacheable: bool = False, strip_scripts: bool = True
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self.route(path, methods=("POST",), cacheable=cacheable, strip_scripts=strip_scripts)

    def put(
        self, path: str, cacheable: bool = False, strip_scripts: bool = True
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self.route(path, methods=("PUT",), cacheable=cacheable, strip_scripts=strip_scripts)

    def delete(
        self, path: str, cacheable: bool = False, strip_scripts: bool = True
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self.route(path, methods=("DELETE",), cacheable=cacheable, strip_scripts=strip_scripts)

    def patch(
        self, path: str, cacheable: bool = False, strip_scripts: bool = True
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self.route(path, methods=("PATCH",), cacheable=cacheable, strip_scripts=strip_scripts)

    def openapi_schema(self) -> Dict[str, Any]:
        paths: Dict[str, Any] = {}
        for st in self._static_routes:
            if st.path in ("/openapi.json", "/docs"):
                continue
            paths.setdefault(st.path, {})[st.method.lower()] = {
                "summary": f"Static {st.path}",
                "responses": {str(st.status_code): {"description": "Static cached response"}},
            }
        for de in self._dyn_routes.values():
            params_spec = [
                {
                    "name": p.name,
                    "in": "path" if p.in_path else "query",
                    "required": p.in_path or not p.has_default,
                    "schema": {"type": "integer" if p.annotation is int else "number" if p.annotation is float else "boolean" if p.annotation is bool else "string"},
                }
                for p in de.param_specs
            ]
            op: Dict[str, Any] = {
                "summary": de.fn.__name__,
                "responses": {"200": {"description": "Successful Response"}},
            }
            if params_spec and not de.takes_request:
                op["parameters"] = params_spec
            paths.setdefault(de.pattern, {})[de.method.lower()] = op
        return {
            "openapi": "3.1.0",
            "info": {"title": self.title, "version": self.version},
            "paths": paths,
        }

    def _run_handler(self, entry: _DynEntry, req_obj: PrimostrataRequest | None, kwargs: Dict[str, Any]) -> Any:
        if req_obj is not None:
            res = entry.fn(req_obj)
        elif kwargs:
            res = entry.fn(**kwargs)
        else:
            res = entry.fn()

        if not entry.is_coro:
            return res

        if not entry.needs_event_loop:
            try:
                res.send(None)
            except StopIteration as st:
                return st.value
            except RuntimeError:
                # Recreate coroutine on event loop if it touched loop-bound primitives
                res.close()
                res = entry.fn(req_obj) if req_obj is not None else (entry.fn(**kwargs) if kwargs else entry.fn())

        loop = self._ensure_async_loop()
        return asyncio.run_coroutine_threadsafe(res, loop).result()

    def _make_callback(self) -> Any:
        routes = self._dyn_routes
        middlewares = self._middlewares
        run_handler = self._run_handler

        def _dispatch(
            _ctx: int,
            route_id: int,
            m_ptr: int,
            m_len: int,
            p_ptr: int,
            p_len: int,
            q_ptr: int,
            q_len: int,
            params_ptr: int,
            params_len: int,
            hdr_ptr: int,
            hdr_len: int,
            body_ptr: int,
            body_len: int,
            out_status: Any,
            out_ct_ptr: int,
            out_ct_cap: int,
            out_ct_len: Any,
            out_body_ptr: int,
            out_body_cap: int,
            out_body_len: Any,
        ) -> int:
            entry = routes.get(route_id)
            if entry is None:
                return -1

            params_dict: Dict[str, str] = {}
            if params_len:
                raw_p = ctypes.string_at(params_ptr, params_len).decode("utf-8", errors="replace")
                for line in raw_p.split("\n"):
                    k, _, v = line.partition("=")
                    if k:
                        params_dict[k] = v

            def _build_req() -> PrimostrataRequest:
                method = ctypes.string_at(m_ptr, m_len).decode("ascii", errors="replace")
                path = ctypes.string_at(p_ptr, p_len).decode("utf-8", errors="replace")
                query = ctypes.string_at(q_ptr, q_len).decode("utf-8", errors="replace") if q_len else ""
                hdrs: Dict[str, str] = {}
                if hdr_len:
                    raw_h = ctypes.string_at(hdr_ptr, hdr_len).decode("utf-8", errors="replace")
                    for line in raw_h.split("\n"):
                        hk, _, hv = line.partition("\t")
                        if hk:
                            hdrs[hk.lower()] = hv
                req_body = ctypes.string_at(body_ptr, body_len) if body_len else b""
                return PrimostrataRequest(
                    method=method,
                    path=path,
                    query=query,
                    params=params_dict,
                    headers=hdrs,
                    body=req_body,
                )

            try:
                if entry.takes_request or middlewares:
                    req_obj = _build_req()
                    if middlewares:
                        def _call_leaf(r: PrimostrataRequest) -> Any:
                            if entry.takes_request:
                                return run_handler(entry, r, {})
                            kw = _resolve_kwargs(entry, r.params, r.query, r.body)
                            return run_handler(entry, None, kw)

                        fn_chain = _call_leaf
                        for mw in reversed(middlewares):
                            nxt = fn_chain
                            fn_chain = lambda r, m=mw, nx=nxt: m(r, nx)
                        result = fn_chain(req_obj)
                    else:
                        result = run_handler(entry, req_obj, {})
                elif entry.param_specs or entry.body_param_name is not None:
                    q_str = ctypes.string_at(q_ptr, q_len).decode("utf-8", errors="replace") if q_len else ""
                    b_raw = ctypes.string_at(body_ptr, body_len) if (entry.body_param_name and body_len) else b""
                    kw = _resolve_kwargs(entry, params_dict, q_str, b_raw)
                    result = run_handler(entry, None, kw)
                else:
                    result = run_handler(entry, None, {})
            except ValueError as ve:
                result = PrimostrataResponse({"detail": str(ve)}, status_code=422)

            status, ct_b, body_b = _coerce_response(result)
            out_status[0] = status
            ct_n = min(len(ct_b), out_ct_cap)
            out_ct_len[0] = ct_n
            if ct_n:
                ctypes.memmove(out_ct_ptr, ct_b, ct_n)

            body_n = len(body_b)
            out_body_len[0] = body_n
            if body_n > out_body_cap:
                return ERR_BUFFER_TOO_SMALL
            if body_n:
                ctypes.memmove(out_body_ptr, body_b, body_n)
            return OK_ALLOW_OR_HIT

        return _DYN_CALLBACK_TYPE(_dispatch)

    def _register_docs_routes(self) -> None:
        if not self._docs:
            return
        existing = {st.path for st in self._static_routes}
        if "/openapi.json" not in existing:
            self.static("/openapi.json", self.openapi_schema(), strip_scripts=False)
        if "/docs" not in existing:
            html = (
                "<!DOCTYPE html><html><head><title>"
                + self.title
                + "</title></head><body><h1>"
                + self.title
                + "</h1><p>OpenAPI schema: <a href='/openapi.json'>/openapi.json</a></p></body></html>"
            )
            self.static("/docs", html, content_type="text/html; charset=utf-8", strip_scripts=False)

    def start(self, host: str = "127.0.0.1", port: int = 0) -> int:
        if self._srv_handle:
            return self.port
        if any(d.needs_event_loop for d in self._dyn_routes.values()):
            self._ensure_async_loop()

        self._register_docs_routes()

        host_b = host.encode("utf-8")
        bound = ctypes.c_uint16(0)
        srv = self._lib.primo_server_create(
            host_b, len(host_b), port, self._workers, ctypes.byref(bound)
        )
        if not srv:
            raise OSError(f"Failed to bind PrimostrataApp on {host}:{port}")

        self._srv_handle = srv
        self.host = host
        self.port = int(bound.value)

        if self._rate_limit_per_sec > 0:
            self._lib.primo_server_set_rate_limit(srv, self._rate_limit_per_sec)

        if self._edge_gate_secret is not None:
            rc = self._lib.primo_server_set_edge_gate(srv, self._edge_gate_secret, 1)
            if rc != 0:
                raise RuntimeError(f"primo_server_set_edge_gate failed rc={rc}")

        for st in self._static_routes:
            m_b = st.method.encode("ascii")
            p_b = st.path.encode("utf-8")
            rc = self._lib.primo_server_add_static_route(
                srv,
                m_b,
                len(m_b),
                p_b,
                len(p_b),
                st.status_code,
                st.content_type,
                len(st.content_type),
                st.body,
                len(st.body),
                1 if st.strip_scripts else 0,
            )
            if rc != 0:
                raise RuntimeError(f"Failed to register static route {st.path}: rc={rc}")

        for de in self._dyn_routes.values():
            m_b = de.method.encode("ascii")
            p_b = de.pattern.encode("utf-8")
            rc = self._lib.primo_server_add_dynamic_route(
                srv,
                de.route_id,
                m_b,
                len(m_b),
                p_b,
                len(p_b),
                1 if de.cacheable else 0,
                1 if de.strip_scripts else 0,
            )
            if rc != 0:
                raise RuntimeError(f"Failed to register dynamic route {de.pattern}: rc={rc}")

        self._cb_ref = self._make_callback()
        rc = self._lib.primo_server_start(srv, self._cb_ref, None)
        if rc != 0:
            raise RuntimeError(f"primo_server_start failed rc={rc}")
        return self.port

    def stop(self) -> None:
        if self._srv_handle:
            self._lib.primo_server_destroy(self._srv_handle)
            self._srv_handle = None
            self._cb_ref = None
        if self._async_loop is not None:
            try:
                self._async_loop.call_soon_threadsafe(self._async_loop.stop)
            except Exception:
                pass
            if self._async_thread is not None:
                self._async_thread.join(timeout=2.0)
                self._async_thread = None
            self._async_loop = None

    def serve(self, host: str = "127.0.0.1", port: int = 8080) -> None:
        self.start(host, port)
        try:
            stop_ev = threading.Event()
            while not stop_ev.wait(1.0):
                pass
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    @contextmanager
    def running(self, host: str = "127.0.0.1", port: int = 0) -> Iterator[str]:
        actual_port = self.start(host, port)
        try:
            yield f"http://{host}:{actual_port}"
        finally:
            self.stop()

    def __del__(self) -> None:
        try:
            self.stop()
        except Exception:
            pass


def _resolve_kwargs(
    entry: _DynEntry, params_dict: Dict[str, str], query_str: str, body_raw: bytes
) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {}
    q_map: Dict[str, str] | None = None
    for spec in entry.param_specs:
        if spec.in_path:
            raw_v = params_dict.get(spec.name)
            if raw_v is None:
                if spec.has_default:
                    kwargs[spec.name] = spec.default
                else:
                    raise ValueError(f"Missing path parameter: {spec.name}")
            else:
                kwargs[spec.name] = _cast_value(raw_v, spec.annotation)
        else:
            if q_map is None:
                q_map = dict(parse_qsl(query_str, keep_blank_values=True)) if query_str else {}
            if spec.name in q_map:
                kwargs[spec.name] = _cast_value(q_map[spec.name], spec.annotation)
            elif spec.has_default:
                kwargs[spec.name] = spec.default
            else:
                raise ValueError(f"Missing required query parameter: {spec.name}")
    if entry.body_param_name is not None:
        kwargs[entry.body_param_name] = _json_loads_bytes(body_raw) if body_raw else {}
    return kwargs


class PrimostrataClient:
    """Native PRM1 binary wire client (zero HTTP text framing + optional ZIN decompression)."""

    def __init__(self, host: str, port: int, use_zin: bool = True) -> None:
        self._sock = socket.create_connection((host, port), timeout=5.0)
        self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._use_zin = use_zin
        self._edge = PrimostrataEdge() if use_zin else None

    def close(self) -> None:
        try:
            self._sock.close()
        except Exception:
            pass
        if self._edge is not None:
            self._edge.close()
            self._edge = None

    def __enter__(self) -> "PrimostrataClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise EOFError("Connection closed by server")
            buf.extend(chunk)
        return bytes(buf)

    def request(self, method: str, target: str, body: bytes = b"") -> Tuple[int, str, bytes]:
        m_b = method.encode("ascii")
        t_b = target.encode("utf-8")
        flags = 1 if self._use_zin else 0
        pkt = _PRM1_HDR.pack(_PRM1_MAGIC, flags, len(m_b), len(t_b), len(body)) + m_b + t_b + body
        self._sock.sendall(pkt)

        hdr = self._recv_exact(_PRM1_RESP_HDR.size)
        magic, status, rflags, ct_len, body_len = _PRM1_RESP_HDR.unpack(hdr)
        if magic != _PRM1_MAGIC:
            raise ValueError(f"Invalid PRM1 magic: {magic!r}")
        tail = self._recv_exact(ct_len + body_len)
        ct = tail[:ct_len].decode("utf-8", errors="replace")
        raw_body = tail[ct_len:]
        if (rflags & 1) and self._edge is not None:
            raw_body = self._edge.decompress(raw_body)
        return status, ct, raw_body

    def get(self, target: str) -> Tuple[int, str, bytes]:
        return self.request("GET", target)

    def post(self, target: str, body: bytes) -> Tuple[int, str, bytes]:
        return self.request("POST", target, body)
