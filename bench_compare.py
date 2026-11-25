from __future__ import annotations

import statistics
import time

from primostrata_edge import EdgeBlockedError, PrimostrataEdge
from pure_python_edge import PureEdgeBlockedError, PurePythonEdge

KEY = b"\x5A" * 32
NONCE = b"\x24" * 12
AAD = b"edge.primostrata.org"

SAMPLE_HTML = (
    "<!DOCTYPE html><html><head><title>Store</title></head><body>"
    + "".join(
        f"<section class='card'><h2>Item {i}</h2><p>Fast edge delivery, deterministic security, zero-copy routing.</p></section>"
        for i in range(40)
    )
    + "<script>console.log('injected_tracker')</script></body></html>"
).encode("utf-8")


def _summarize(name: str, lats_ns: list[int], total_ns: int, blocked: int, hits: int, wire_bytes: int):
    lats_ns.sort()
    n = len(lats_ns)
    rps = (n * 1_000_000_000) / max(1, total_ns)
    p50_us = lats_ns[int(n * 0.50)] / 1000.0
    p99_us = lats_ns[int(n * 0.99)] / 1000.0
    mean_us = statistics.fmean(lats_ns) / 1000.0
    print(
        f"  {name:<26} | {rps:>10,.0f} req/s | mean {mean_us:>7.2f} us | p50 {p50_us:>6.2f} us | p99 {p99_us:>7.2f} us | blk={blocked} hit={hits} wire={wire_bytes//1024} KB"
    )


def bench_waf_only(primo: PrimostrataEdge, pure: PurePythonEdge, n: int = 20_000):
    print(f"\n=== 1. L4/L7 WAF + SSRF + Smuggling Inspection ({n:,} requests: 70% honest, 30% attacks) ===")
    cases = []
    hdr_ok = [("Host", "edge.primostrata.org"), ("Accept-Encoding", "br, gzip, zin")]
    hdr_smug = [("Host", "edge.primostrata.org"), ("Content-Length", "10"), ("Transfer-Encoding", "chunked")]
    attacks = [
        ("http://169.254.169.254/latest/meta-data/", hdr_ok),
        ("http://2130706433/admin", hdr_ok),
        ("https://edge.primostrata.org/search?q=1+union%20select+pass", hdr_ok),
        ("https://edge.primostrata.org/files/../../etc/passwd", hdr_ok),
        ("https://edge.primostrata.org/api", hdr_smug),
        ("https://edge.primostrata.org/?q=<script>alert(1)</script>", hdr_ok),
    ]
    for i in range(n):
        if i % 10 < 7:
            cases.append((f"https://edge.primostrata.org/items/{i % 50}?page={i % 5}", hdr_ok))
        else:
            cases.append(attacks[i % len(attacks)])

    for label, engine in (("Pure Python (stdlib+ipaddr)", pure), ("Primostrata Edge SDK (Rust)", primo)):
        lats = []
        blk = 0
        t0 = time.perf_counter_ns()
        for url, hdrs in cases:
            s = time.perf_counter_ns()
            ok = engine.inspect(url, hdrs)
            lats.append(time.perf_counter_ns() - s)
            if not ok:
                blk += 1
        total = time.perf_counter_ns() - t0
        _summarize(label, lats, total, blk, 0, 0)


def bench_dynamic_pipeline(primo: PrimostrataEdge, pure: PurePythonEdge, n: int = 5_000):
    print(f"\n=== 2. Dynamic Pipeline (WAF + <script> Strip + Compress + ChaCha20-Poly1305 AEAD, {len(SAMPLE_HTML)} B HTML, {n:,} misses) ===")
    hdr_ok = [("Host", "edge.primostrata.org")]
    for label, engine, exc in (
        ("Pure Python (zlib+crypto)", pure, PureEdgeBlockedError),
        ("Primostrata Edge SDK (Rust)", primo, EdgeBlockedError),
    ):
        engine.reset()
        lats = []
        wire = 0
        t0 = time.perf_counter_ns()
        for i in range(n):
            url = f"https://edge.primostrata.org/dyn/{i}"
            s = time.perf_counter_ns()
            res = engine.handle_request(url, hdr_ok, SAMPLE_HTML, KEY, NONCE, AAD, cacheable=False)
            lats.append(time.perf_counter_ns() - s)
            wire += len(res.sealed_wire)
        total = time.perf_counter_ns() - t0
        _summarize(label, lats, total, 0, 0, wire)


def bench_mixed_edge(primo: PrimostrataEdge, pure: PurePythonEdge, n: int = 15_000):
    print(f"\n=== 3. Mixed Production Workload (55% Cacheable + 20% Dynamic Miss + 25% L7 Attacks, {n:,} requests) ===")
    hdr_ok = [("Host", "edge.primostrata.org"), ("Accept-Encoding", "zin, gzip")]
    hdr_smug = [("Host", "edge.primostrata.org"), ("Content-Length", "5"), ("Transfer-Encoding", "chunked")]
    workload = []
    for i in range(n):
        m = i % 20
        if m < 11:
            workload.append((f"https://edge.primostrata.org/hot/{i % 24}", hdr_ok, True))
        elif m < 15:
            workload.append((f"https://edge.primostrata.org/dyn/{i}", hdr_ok, False))
        elif m == 15:
            workload.append(("http://169.254.169.254/latest/meta-data/", hdr_ok, False))
        elif m == 16:
            workload.append(("http://0x7f000001/admin", hdr_ok, False))
        elif m == 17:
            workload.append(("https://edge.primostrata.org/api", hdr_smug, False))
        elif m == 18:
            workload.append(("https://edge.primostrata.org/q?x=<script>1</script>", hdr_ok, False))
        else:
            workload.append(("https://edge.primostrata.org/a/../../etc/passwd", hdr_ok, False))

    for label, engine, exc in (
        ("Pure Python Equivalent", pure, PureEdgeBlockedError),
        ("Primostrata Edge SDK", primo, EdgeBlockedError),
    ):
        engine.reset()
        lats = []
        blk = 0
        hits = 0
        wire = 0
        t0 = time.perf_counter_ns()
        for url, hdrs, cacheable in workload:
            s = time.perf_counter_ns()
            try:
                res = engine.handle_request(url, hdrs, SAMPLE_HTML, KEY, NONCE, AAD, cacheable=cacheable)
                if res.cache_hit:
                    hits += 1
                wire += len(res.sealed_wire)
            except exc:
                blk += 1
            lats.append(time.perf_counter_ns() - s)
        total = time.perf_counter_ns() - t0
        _summarize(label, lats, total, blk, hits, wire)


def main():
    with PrimostrataEdge() as primo:
        pure = PurePythonEdge()
        bench_waf_only(primo, pure)
        bench_dynamic_pipeline(primo, pure)
        bench_mixed_edge(primo, pure)


if __name__ == "__main__":
    main()
