# Primostrata Edge SDK for Python

Compiled native Rust web runtime, **L4/L7 WAF (`SHIELD`)**, **per-core `REG 0.7` async I/O multiplexer**, **edge cache (`STORE64`)**, **`ZIN` lossless compression**, **`ChaCha20-Poly1305` AEAD**, and dual **`HTTP/1.1` + `PRM1` binary wire protocol** exposed as a standalone binary Python package (`primostrata_edge.dll`, Windows `x86_64` prebuilt included; core Rust engine sources remain proprietary).

---

## Key Features

- **`PrimostrataApp` — Drop-in Web Framework (replaces `FastAPI + Uvicorn`)**
  - Non-blocking TCP/HTTP/1.1 keep-alive multiplexer (`REG 0.7` per-core worker scheduling) — L4/L7 inspection, rate limiting, static routes, HTML `<script>` stripping, and cached responses run in native Rust **before touching the Python GIL**.
  - Supports both `def` and `async def` handlers (inline coroutine fast-path + automatic background `asyncio` event loop fallback for `await` I/O), typed path/query parameters with `422` validation, `orjson` serialization, auto `/openapi.json` & `/docs`, and `@app.middleware`.
  - Simultaneous **`PRM1` Binary Wire** on the same port (`PrimostrataClient`) with optional `ZIN` response compression.
- **`PrimostrataEdge` — Embedded Edge SDK & `PrimostrataEdgeMiddleware` for FastAPI/Starlette**
  - L4/L7 security inspection (IPv4/IPv6 SSRF including decimal/hex/octal obfuscation, `CL+TE`/duplicate `Content-Length` HTTP smuggling, traversal, CRLF injection, SQLi/XSS).
  - Single-pass `<script>` stripping, `ZIN` compression, `ChaCha20-Poly1305` AEAD seal/open, and per-flow rate limiting.
- **`pure_python_edge` — Full Pure-Python Reference Equivalent**
  - Complete functional equivalent (`ipaddress`, `re`, `zlib`, `cryptography`, `OrderedDict`) included for parity testing and apples-to-apples benchmarking.

---

## Quickstart

```python
import asyncio
from primostrata_edge import PrimostrataApp

app = PrimostrataApp(workers=4)
app.static("/health", {"status": "ok", "engine": "primostrata"})

@app.get("/users/{uid}")
async def get_user(uid: int, page: int = 1):
    return {"uid": uid, "page": page, "role": "merchant"}

@app.get("/async-io")
async def slow_io():
    await asyncio.sleep(0.01)
    return {"awaited": True}

if __name__ == "__main__":
    app.serve(host="127.0.0.1", port=8080)
```

---

## Verified Parity Tests

```bash
python -m pytest -v tests/
```

Covers all security vectors (honest traffic, SSRF IPv4/IPv6/decimal/hex/octal/userinfo/`.internal`, traversal, CRLF, SQLi/XSS, HTTP smuggling), cache hit/miss & AEAD roundtrip/tamper rejection, rate limiting, FastAPI middleware parity, high-concurrency `async def` (`await asyncio.sleep`), and `PRM1` binary wire (`6/6` tests passing).

---

## Reproducible Benchmarks (Windows `x86_64`, Python 3.14)

All multi-server web benchmarks run each server in its own isolated subprocess (`workers=4` / `runtime-threads=4`) driven by external Rust **`oha 1.17.0`** and Go **`k6 2.4.0`**. `PrimostrataApp` keeps `SHIELD` WAF + `EdgeGate` enabled on **every request**, while bare baselines run with **no WAF**.

### 1. `[oha 1.17.0]` Static / `const=True` `/health` (`c=32`, 3s HTTP/1.1 Keep-Alive)

| Stack | RPS | Avg | p50 | p90 | p99 | `HTTP 200` |
|---|---:|---:|---:|---:|---:|---:|
| `Uvicorn(w=4)+FastAPI (NO WAF)` | `16,391.9 req/s` | `1.95 ms` | `1.94 ms` | `2.47 ms` | `3.38 ms` | `49,208` |
| `Granian(t=4)+BlackSheep (NO WAF)` | `7,321.6 req/s` | `4.37 ms` | `4.34 ms` | `4.78 ms` | `5.40 ms` | `22,050` |
| `Granian(t=4)+BlackSheep + WAF` | `5,424.8 req/s` | `5.89 ms` | `5.84 ms` | `6.35 ms` | `7.84 ms` | `16,318` |
| `Robyn(w=4, const+dyn, NO WAF)` | `97,720.0 req/s` | `0.32 ms` | `0.28 ms` | `0.50 ms` | `0.79 ms` | `293,698` |
| **`PrimostrataApp(w=4, REG+SHIELD)`** | **`116,689.3 req/s`** | **`0.27 ms`** | **`0.25 ms`** | **`0.37 ms`** | **`0.64 ms`** | **`350,872`** |

### 2. `[oha 1.17.0]` Async Dynamic `/users/{uid}` (`c=32`, 3s Keep-Alive — Python invoked per request)

| Stack | RPS | Avg | p50 | p90 | p99 | `HTTP 200` |
|---|---:|---:|---:|---:|---:|---:|
| `Uvicorn(w=4)+FastAPI (NO WAF)` | `15,066.0 req/s` | `2.12 ms` | `2.18 ms` | `2.56 ms` | `3.04 ms` | `45,396` |
| `Granian(t=4)+BlackSheep (NO WAF)` | `7,263.4 req/s` | `4.40 ms` | `4.38 ms` | `4.77 ms` | `5.25 ms` | `21,772` |
| `Granian(t=4)+BlackSheep + WAF` | `5,410.2 req/s` | `5.91 ms` | `5.89 ms` | `6.35 ms` | `6.96 ms` | `16,224` |
| `Robyn(w=4, const+dyn, NO WAF)` | `11,698.0 req/s` | `2.73 ms` | `2.61 ms` | `3.17 ms` | `5.29 ms` | `35,239` |
| **`PrimostrataApp(w=4, REG+SHIELD)`** | **`15,417.7 req/s`** | **`2.07 ms`** | **`2.03 ms`** | **`2.57 ms`** | **`3.20 ms`** | **`46,295`** |

### 3. `[k6 2.4.0]` Mixed Edge Traffic (50% Static `/health` + 20% Dynamic `/users/{uid}` + 30% L7 Attacks, 20 VUs, 4s)

| Stack | RPS | Avg | p50 | p90 | p99 | Total / Checks |
|---|---:|---:|---:|---:|---:|---|
| `Uvicorn(w=4)+FastAPI (NO WAF)` | `12,866.9 req/s` | `1.47 ms` | `1.47 ms` | `2.21 ms` | `3.05 ms` | `51,493 (100%)` |
| `Granian(t=4)+BlackSheep (NO WAF)` | `6,764.5 req/s` | `2.88 ms` | `2.73 ms` | `3.31 ms` | `4.15 ms` | `27,077 (100%)` |
| `Granian(t=4)+BlackSheep + WAF` | `5,856.3 req/s` | `3.33 ms` | `3.22 ms` | `4.20 ms` | `5.66 ms` | `23,443 (100%)` |
| `Robyn(w=4, const+dyn, NO WAF)` | `24,778.9 req/s` | `0.72 ms` | `0.66 ms` | `1.51 ms` | `2.53 ms` | `99,180 (100%)` |
| **`PrimostrataApp(w=4, REG+SHIELD)`** | **`38,099.7 req/s`** | **`0.39 ms`** | **`0.00 ms*`** | **`1.01 ms`** | **`2.51 ms`** | **`152,431 (100%)`** |

*\*`k6` on Windows reports `0.00 ms` when median response latency is sub-millisecond (`avg = 0.39 ms`).*

### 4. In-Process SDK Pipeline vs Pure-Python Equivalent (`bench_compare.py`)

- **L4/L7 WAF + SSRF + Smuggling (`20,000` req):** `PrimostrataEdge` **`346,494 req/s`** (`p99 5.10 us`) vs `PurePythonEdge` `73,430 req/s` (`p99 27.00 us`) — **4.7x faster**.
- **Mixed Cache + Dynamic Miss + Attacks (`15,000` req):** `PrimostrataEdge` **`81,594 req/s`** (`p50 7.20 us`) vs `PurePythonEdge` `45,384 req/s` (`p50 17.80 us`) — **1.8x faster**.
- **Uncached Dynamic Miss (`5,000` HTML 4792B `<script>` strip + compress + AEAD):** `PrimostrataEdge` `28,264 req/s` vs `PurePythonEdge (zlib C + OpenSSL)` `30,520 req/s`.

---

## Reproduce Locally

```bash
python -m pytest -v tests/
python bench_compare.py
python bench_external_intl.py
```

Note: Prebuilt native binary included for **Windows `x86_64`** (`primostrata_edge/primostrata_edge.dll`). Source code for the underlying Rust engine is proprietary and excluded from this repository.
