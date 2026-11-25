# Native Core Subsystems & Request Flow

`primostrata-edge` separates network I/O, protocol framing, perimeter inspection, caching, compression, and transport encryption into compiled native binaries (`primostrata_edge.dll` / `libprimostrata_edge.so`), invoking Python only when a request misses static routes and the per-worker edge cache.

## Request lifecycle (`PrimostrataApp`)

```text
TCP socket accept
  └─> I/O & Core Scheduler (routes connection by compact request/flow signature)
        └─> Non-blocking worker loop (HTTP/1.1 keep-alive + PRM1 binary framing)
              ├─> Rate Limiter (per-worker per-second IP bucket)        ──> 429 JSON
              ├─> Optional PoW / Bot Gate (X-Primo-PoW check)           ──> 403 JSON
              ├─> L4/L7 Security Inspection (URL, headers, SQLi/XSS)    ──> 403 JSON
              ├─> Static route table (zero GIL, pre-compressed cache)   ──> 200
              ├─> Per-worker GET cache (64-bit hashed lookup)           ──> 200
              └─> Python handler bridge (CFUNCTYPE + GIL)
                    ├─> async def (no await): inline coro.send(None)
                    ├─> async def (with await): background asyncio loop
                    └─> return value -> optional HTML <script> strip
                                     -> optional ZIN compression
                                     -> cache store (if cacheable)
                                     -> non-blocking socket flush
```

## Subsystems inside the native binary

| Subsystem | Role | Execution boundary |
|---|---|---|
| **I/O & Core Scheduler** | Non-blocking `TcpListener` / `TcpStream` multiplexer across `workers` OS threads (`TCP_NODELAY`, HTTP pipelining, `PRM1` framing). Adaptive spin/park when idle (`0` threads spawned per connection). | Native (no Python GIL) |
| **L4/L7 Security Filter** | Fail-closed inspection of URL schemes, ASCII bounds, `\` and traversal (`..`, `%2e`, `%5c`, `%0d`, `%0a`, `%00`), SSRF (IPv4/IPv6 private/loopback/link-local plus decimal/hex/octal obfuscation like `2130706433` or `0177.0.0.1`), HTTP smuggling (`CL+TE`, duplicate `Content-Length`), and SQLi/XSS payloads. | Native (no Python GIL) |
| **HTML Sanitizer** | Single-pass `<script>...</script>` tag removal applied selectively per route (`strip_scripts=True` by default on HTML responses; disable with `strip_scripts=False` for trusted SPA/JS pages). | Native (no Python GIL) |
| **Per-Worker Cache & Codec** | Lock-free per-worker LRU response cache (`2,048` entries/worker) keyed by 64-bit hashes, plus streaming lossless `ZIN` compression using pre-allocated per-worker scratch buffers (`Accept-Encoding: zin` or `PRM1` flag `1`). | Native (no Python GIL) |
| **Transport Crypto (`AEAD`)** | Authenticated encryption (`ChaCha20-Poly1305` per RFC 8439) for `PrimostrataEdge.seal` / `open` / `handle_request`. | Native (no Python GIL) |
| **Python Bridge** (`app.py` / `sdk.py`) | `ctypes` bindings, zero-overcopy `ctypes.string_at` / `memmove` payload transfer, `GET_AWAITABLE` bytecode check for inline vs event-loop coroutine dispatch, typed path/query casting (`int`, `float`, `bool`, `str`), `orjson` serialization, static `/openapi.json` & `/docs`. | Python |

## Design trade-offs

- **No work-stealing cross-thread locks on the hot path:** static responses, cache hits, rate-limit rejections, and `403` security blocks never contend on Python's GIL or cross-worker cache mutexes.
- **Per-worker cache consistency:** when `cacheable=True` is set on a `GET` route, each worker warms its own local cache entry independently rather than synchronizing a shared global LRU across workers.
- **Native worker callbacks & thread-locals:** see [API Reference — Threading & DB Pools](api.md#threading-and-db-connection-pools) before using `threading.local()` inside handlers.
