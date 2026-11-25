# primostrata-edge

Fast HTTP/1.1 + binary `PRM1` web runtime and L4/L7 edge security SDK for Python, shipped as compiled native binaries (`primostrata_edge.dll` for Windows x64, `libprimostrata_edge.so` for Linux x64) with a pure-Python reference implementation for parity testing and benchmarking.

## What's in this repository

- `primostrata_edge/`
  - `app.py` — `PrimostrataApp` (native HTTP/1.1 + `PRM1` server, `@app.get`/`@app.post`, `def` and `async def` routes, typed path/query params with `422` validation, `orjson` responses, `/openapi.json`, `/docs`), `PrimostrataClient`.
  - `sdk.py` — `PrimostrataEdge` low-level bindings (request inspection, `<script>` stripping, `ZIN` compression, `ChaCha20-Poly1305` AEAD, rate limiting).
  - `middleware.py` — `PrimostrataEdgeMiddleware` for existing FastAPI/Starlette apps.
  - `primostrata_edge.dll` / `libprimostrata_edge.so` — prebuilt native core.
- `pure_python_edge/` — functional equivalent in Python (`ipaddress`, `re`, `zlib`, `cryptography`, `OrderedDict`) implementing the same checks and pipeline.
- `docs/` — [API Reference](docs/api.md) (including per-worker threading/DB pool behavior) and [Native Subsystems Architecture](docs/architecture.md).
- `examples/concert_booking/` — full-stack ticket storefront (`HTML`/`JS`, SSR XSS stripping, atomic `SQLite WAL` orders, `k6`/`oha` comparison vs FastAPI + Uvicorn).
- `tests/` — parity tests between native SDK and pure Python, HTTP/1.1 + `PRM1` server checks, `async/await` concurrency (`24` concurrent clients across `4` workers), and rate limits (`6/6` passing).
- `bench_*.py` — reproducible benchmark scripts (`bench_compare.py`, `bench_top_python.py`, `bench_external_intl.py` for `oha` and `k6`).

## Usage

### Standalone web server (`PrimostrataApp`)

```python
import asyncio
from primostrata_edge import PrimostrataApp

app = PrimostrataApp(workers=4)
app.static("/health", {"status": "ok"})

@app.get("/users/{uid}")
async def get_user(uid: int, page: int = 1):
    return {"uid": uid, "page": page}

@app.get("/io")
async def async_io():
    await asyncio.sleep(0.01)
    return {"done": True}

if __name__ == "__main__":
    app.serve(host="127.0.0.1", port=8080)
```

### As FastAPI/Starlette middleware

```python
from fastapi import FastAPI
from primostrata_edge.middleware import PrimostrataEdgeMiddleware

app = FastAPI()
app.add_middleware(PrimostrataEdgeMiddleware)
```

## How the package works

- Socket multiplexing, HTTP/1.1 keep-alive parsing, L4/L7 validation (IPv4/IPv6 SSRF including obfuscated decimal/hex/octal IPs, `CL+TE` / duplicate `Content-Length` smuggling, traversal, CRLF, SQLi/XSS), rate limiting, static routes, and cached `GET` responses run inside the native binary before acquiring the Python GIL.
- Each native worker core maintains its own pre-allocated compression scratch buffer and local response cache keyed by request/flow signatures to avoid cross-thread lock contention.
- `async def` handlers without suspension points run inline via `coro.send(None)`; handlers that `await` I/O automatically dispatch to a background `asyncio` loop thread without blocking socket workers.
- Binary `PRM1` requests (`PrimostrataClient`) share the same TCP port alongside standard HTTP/1.1.

## Benchmarks

Environment: Windows 11 x86_64, Python 3.14.7. Each server runs in its own isolated subprocess (`4` workers / `4` runtime threads), driven externally by **`oha 1.17.0`** and **`k6 2.4.0`**. `PrimostrataApp` runs with L4/L7 WAF enabled on every request; bare baselines run without WAF.

### `oha 1.17.0`: `GET /health` (`c=32`, 3s keep-alive)

| Stack | RPS | Avg | p50 | p90 | p99 | `200 OK` |
|---|---:|---:|---:|---:|---:|---:|
| `Uvicorn(w=4) + FastAPI (no WAF)` | `16,391.9` | `1.95 ms` | `1.94 ms` | `2.47 ms` | `3.38 ms` | `49,208` |
| `Granian(t=4) + BlackSheep (no WAF)` | `7,321.6` | `4.37 ms` | `4.34 ms` | `4.78 ms` | `5.40 ms` | `22,050` |
| `Granian(t=4) + BlackSheep + WAF` | `5,424.8` | `5.89 ms` | `5.84 ms` | `6.35 ms` | `7.84 ms` | `16,318` |
| `Robyn(w=4, const=True, no WAF)` | `97,720.0` | `0.32 ms` | `0.28 ms` | `0.50 ms` | `0.79 ms` | `293,698` |
| `PrimostrataApp(w=4, +WAF)` | `116,689.3` | `0.27 ms` | `0.25 ms` | `0.37 ms` | `0.64 ms` | `350,872` |

### `oha 1.17.0`: `GET /users/42` dynamic `async def` (`c=32`, 3s keep-alive)

| Stack | RPS | Avg | p50 | p90 | p99 | `200 OK` |
|---|---:|---:|---:|---:|---:|---:|
| `Uvicorn(w=4) + FastAPI (no WAF)` | `15,066.0` | `2.12 ms` | `2.18 ms` | `2.56 ms` | `3.04 ms` | `45,396` |
| `Granian(t=4) + BlackSheep (no WAF)` | `7,263.4` | `4.40 ms` | `4.38 ms` | `4.77 ms` | `5.25 ms` | `21,772` |
| `Granian(t=4) + BlackSheep + WAF` | `5,410.2` | `5.91 ms` | `5.89 ms` | `6.35 ms` | `6.96 ms` | `16,224` |
| `Robyn(w=4, dynamic, no WAF)` | `11,698.0` | `2.73 ms` | `2.61 ms` | `3.17 ms` | `5.29 ms` | `35,239` |
| `PrimostrataApp(w=4, +WAF)` | `15,417.7` | `2.07 ms` | `2.03 ms` | `2.57 ms` | `3.20 ms` | `46,295` |

### `k6 2.4.0`: mixed traffic (50% static, 20% dynamic, 30% L7 attacks, 20 VUs, 4s)

| Stack | RPS | Avg | p50 | p90 | p99 | Requests / Checks |
|---|---:|---:|---:|---:|---:|---|
| `Uvicorn(w=4) + FastAPI (no WAF)` | `12,866.9` | `1.47 ms` | `1.47 ms` | `2.21 ms` | `3.05 ms` | `51,493 (100%)` |
| `Granian(t=4) + BlackSheep (no WAF)` | `6,764.5` | `2.88 ms` | `2.73 ms` | `3.31 ms` | `4.15 ms` | `27,077 (100%)` |
| `Granian(t=4) + BlackSheep + WAF` | `5,856.3` | `3.33 ms` | `3.22 ms` | `4.20 ms` | `5.66 ms` | `23,443 (100%)` |
| `Robyn(w=4, no WAF)` | `24,778.9` | `0.72 ms` | `0.66 ms` | `1.51 ms` | `2.53 ms` | `99,180 (100%)` |
| `PrimostrataApp(w=4, +WAF)` | `38,099.7` | `0.39 ms` | `0.00 ms*` | `1.01 ms` | `2.51 ms` | `152,431 (100%)` |

*\*`k6` reports `0.00 ms` on Windows when median latency is sub-millisecond (`avg = 0.39 ms`).*

### Full-stack website (`examples/concert_booking/`, HTML + SQLite WAL + XSS stripping)

End-to-end storefront (`GET /`), SSR concert detail with `<script>` sanitization (`GET /concerts/{cid}`), SQLite WAL catalog read (`GET /api/concerts`), atomic `BEGIN IMMEDIATE` order write (`POST /api/orders`), and DB invariant check (`/api/audit`, `invariant_ok=True` across all runs):

| Workload | `FastAPI+Uvicorn (w=4, no WAF)` | `FastAPI+Uvicorn (w=4, +WAF)` | `PrimostrataApp (w=4, +WAF)` |
|---|---:|---:|---:|
| `[oha]` Storefront `GET /` (`c=32`) | `6,144.0 req/s` (`p99 7.60 ms`) | `4,797.4 req/s` (`p99 11.52 ms`) | `91,550.1 req/s` (`p99 0.98 ms`) |
| `[oha]` SQLite WAL read `GET /api/concerts` (`c=32`) | `3,923.8 req/s` (`p99 12.78 ms`) | `3,626.7 req/s` (`p99 20.17 ms`) | `11,169.4 req/s` (`p99 3.78 ms`) |
| `[oha]` SQLite WAL write `POST /api/orders` (`c=16`) | `1,683.4 req/s` (`p99 94.24 ms`) | `815.1 req/s` (`p99 65.19 ms`) | `4,773.3 req/s` (`p99 7.94 ms`) |
| `[k6]` Mixed site + L7 bots (`20 VUs`, 4s) | `3,463.6 req/s` (`p99 19.87 ms`) | `3,231.4 req/s` (`p99 33.46 ms`) | `13,266.8 req/s` (`p99 4.55 ms`) |

### In-process SDK vs `pure_python_edge` (`bench_compare.py`)

- L4/L7 inspection (`20,000` req, 30% attacks): `346,494 req/s` (`p99 5.10 us`) vs `73,430 req/s` (`p99 27.00 us`)
- Mixed workload (`15,000` req, cache hits + misses + attacks): `81,594 req/s` (`p50 7.20 us`) vs `45,384 req/s` (`p50 17.80 us`)
- Uncached dynamic miss (`5,000` x 4792B HTML strip + compress + AEAD): `28,264 req/s` vs `30,520 req/s` (`zlib` + `cryptography`)

## Run tests and benchmarks

```bash
python -m pytest -v tests/
python bench_compare.py
python bench_external_intl.py
python -m examples.concert_booking.run_and_verify
```

Prebuilt native libraries are included for Windows x86_64 and Linux x86_64 (`primostrata_edge/`); Rust engine sources are closed.
