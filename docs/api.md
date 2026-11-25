# API Reference

## `PrimostrataApp` (`primostrata_edge.app`)

Standalone HTTP/1.1 + binary `PRM1` server and router replacing `FastAPI + Uvicorn`.

### Constructor

```python
PrimostrataApp(
    title: str = "Primostrata Edge API",
    version: str = "1.0.0",
    rate_limit_per_sec: int = 0,
    workers: int = 4,
    edge_gate_secret: bytes | None = None,
    docs: bool = True,
    lib_path: str | None = None,
)
```

- `rate_limit_per_sec`: per-worker per-IP request cap per second (`0` disables rate limiting). Exceeded requests return HTTP `429` from native code.
- `workers`: number of native worker threads (`1..=32`).
- `edge_gate_secret`: optional non-zero `32`-byte key enabling PoW verification (`X-Primo-PoW: <challenge_hex>:<solution_hex>`) on incoming requests.
- `docs`: when `True`, serves static `/openapi.json` and `/docs` directly from native memory.
- `lib_path`: optional explicit path to `primostrata_edge.dll` / `libprimostrata_edge.so` (defaults to matching the current OS via `_default_lib_path()` or `PRIMOSTRATA_EDGE_LIB`).

### Route Registration

- **`app.static(path, content, status_code=200, content_type=None, method="GET", strip_scripts=True)`**
  Registers a response served directly from native memory without acquiring the Python GIL.
  > **Important for frontend HTML pages:** set `strip_scripts=False` when serving your own HTML containing `<script>` UI code (otherwise the sanitizer removes `<script>...</script>` tags). Keep `strip_scripts=True` on untrusted SSR HTML routes.
- **`app.get / post / put / delete / patch(path, cacheable=False, strip_scripts=True)`**
  Registers a synchronous (`def`) or asynchronous (`async def`) Python handler.
  - Supports exact routes (`/api/orders`) and path parameters (`/concerts/{cid}`).
  - Annotated parameters (`uid: int`, `page: int = 1`, `flag: bool = False`) are automatically cast from path or query strings; invalid values return HTTP `422`.
  - Declaring `req: PrimostrataRequest` (or `request`) injects the full request object (`req.method`, `req.path`, `req.query`, `req.params`, `req.headers`, `req.body`, `req.json()`, `req.text`).
  - Declaring `body` or `payload` parses the JSON request body automatically.
  - Handlers may return `dict`, `list`, `str`, `bytes`, or `PrimostrataResponse(content, status_code=200, content_type=None)`.
- **`@app.middleware`**
  Registers a Python middleware `fn(request: PrimostrataRequest, call_next) -> response` for dynamic routes.

### Lifecycle Methods

- `app.start(host="127.0.0.1", port=0) -> int` — binds listener, spawns native worker pool, returns actual bound port.
- `app.stop() -> None` — stops workers and closes the background `asyncio` loop cleanly.
- `app.serve(host="127.0.0.1", port=8080) -> None` — blocking server loop (handles `KeyboardInterrupt`).
- `with app.running(host="127.0.0.1", port=0) as base_url:` — context manager returning `http://{host}:{port}`.

### Threading and DB Connection Pools

Dynamic handlers run directly on the `workers` native worker threads via `ctypes.CFUNCTYPE`. Because CPython tears down temporary thread-state dicts on `PyGILState_Release()`, **standard `threading.local()` does not persist between calls on native threads** (a new DB connection would be opened per request).

Instead, either:
1. Key per-worker resources (such as persistent `sqlite3.Connection` handles) by **`threading.get_native_id()`**, or
2. Use an explicit thread-safe pool such as `queue.LifoQueue` / connection pool.

See [examples/concert_booking/db.py](../examples/concert_booking/db.py) for a working `sqlite3` WAL pool example.

---

## `PrimostrataClient` (`primostrata_edge.app`)

Persistent TCP client for the binary `PRM1` protocol sharing the same port as HTTP/1.1.

```python
with PrimostrataClient("127.0.0.1", app.port, use_zin=True) as cli:
    status, content_type, body = cli.get("/concerts")
    status, content_type, body = cli.post("/orders", b'{"concert_id":1,"qty":1}')
```

---

## `PrimostrataEdge` (`primostrata_edge.sdk`)

In-process native wrapper used directly or via `PrimostrataEdgeMiddleware`.

- `inspect(url, headers=()) -> bool` — returns `False` on invalid URLs, SSRF targets, smuggling headers, traversal, CRLF, or SQLi/XSS patterns.
- `strip_scripts(html) -> bytes` — removes `<script>...</script>` blocks in native code.
- `compress(data, level=1) -> bytes` / `decompress(data) -> bytes` — lossless `ZIN` codec roundtrip.
- `seal(key32, nonce12, aad, plaintext) -> bytes` / `open(key32, nonce12, aad, wire) -> bytes` — `ChaCha20-Poly1305` AEAD.
- `handle_request(url, headers, html, key, nonce, aad, flow_hash=1, epoch_sec=1, rate_limit_per_sec=0, cacheable=True) -> EdgeResult` — single FFI call executing rate-limit, L4/L7 check, `<script>` strip, `ZIN` compression, cache lookup/store, and AEAD seal. Raises `EdgeBlockedError` or `EdgeRateLimitedError`.
- `reset() -> None` / `close() -> None`.

---

## `PrimoStore` (`primostrata_edge.store`)

Crash-safe `CubePoint64` WAL key-value & atomic counter store (`durable_sync=True` for `fsync` per write):

- `put(key, val) -> None`
- `get(key) -> bytes | None`
- `decr_if_ge(key, qty, init_if_missing=0) -> tuple[bool, int]` — atomic check-and-decrement inventory counter.
- `get_counter(key) -> int | None`
- `flush() -> None` / `stats() -> tuple[int, int]` (`seq, records`) / `close() -> None`

---

## `PrimoSearch` (`primostrata_edge.search`)

Hybrid ALX-24 lexical + cross-script phonetic conduit + VEC31 2-bit ANN search index:

- `add_doc(doc_id, text, vec64=None) -> None`
- `query(text="", top_k=10, vec64=None) -> list[tuple[int, int]]` — returns `(doc_id, score)` sorted descending.
- `close() -> None`

---

## `PrimostrataEdgeMiddleware` (`primostrata_edge.middleware`)

Starlette / FastAPI `BaseHTTPMiddleware` adapter:

```python
from fastapi import FastAPI
from primostrata_edge.middleware import PrimostrataEdgeMiddleware

app = FastAPI()
app.add_middleware(PrimostrataEdgeMiddleware, strip_html_scripts=True)
```

Rejects invalid requests with HTTP `403` and strips `<script>` tags from `text/html` responses.
