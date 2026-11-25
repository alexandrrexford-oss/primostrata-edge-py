from __future__ import annotations

import os
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time

from primostrata_edge import PrimostrataApp, PrimostrataClient

APPS_CODE = """
import json
import sys
from fastapi import FastAPI
from blacksheep import Application, Response, Content
from blacksheep.server.routing import Router
from blacksheep import json as bs_json
from pure_python_edge import PurePythonEdge

# --- 1. FastAPI ---
fastapi_bare = FastAPI()

@fastapi_bare.get("/health")
def fa_health():
    return {"status": "ok", "engine": "fastapi"}

@fastapi_bare.get("/users/{uid}")
def fa_user(uid: str):
    return {"uid": uid, "role": "merchant"}

# --- 2. BlackSheep (Bare & +Native PurePy WAF Middleware) ---
bs_bare = Application(router=Router())

@bs_bare.router.get("/health")
async def bsb_health():
    return bs_json({"status": "ok", "engine": "blacksheep"})

@bs_bare.router.get("/users/{uid}")
async def bsb_user(uid: str):
    return bs_json({"uid": uid, "role": "merchant"})

bs_waf = Application(router=Router())
_edge = PurePythonEdge()

async def waf_middleware(request, handler):
    url = f"https://edge.primostrata.org{request.url.value.decode('latin1')}"
    hdrs = [(k.decode('latin1'), v.decode('latin1')) for k, v in request.headers]
    if not _edge.inspect(url, hdrs):
        return Response(403, content=Content(b"application/json", b'{"detail":"Blocked"}'))
    return await handler(request)

bs_waf.middlewares.append(waf_middleware)

@bs_waf.router.get("/health")
async def bsw_health():
    return bs_json({"status": "ok", "engine": "blacksheep+waf"})

@bs_waf.router.get("/users/{uid}")
async def bsw_user(uid: str):
    return bs_json({"uid": uid, "role": "merchant"})
"""

ROBYN_CODE = """
import sys
from robyn import Robyn, jsonify

app = Robyn(__file__)

@app.get("/health", const=True)
def rb_health(request):
    return jsonify({"status": "ok", "engine": "robyn"})

@app.get("/users/:uid")
def rb_user(request):
    uid = request.path_params.get("uid", "")
    return jsonify({"uid": uid, "role": "merchant"})

if __name__ == "__main__":
    app.start(host="127.0.0.1", port=int(sys.argv[1]), _check_port=False)
"""


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_port(host: str, port: int, proc: subprocess.Popen | None = None, name: str = "", timeout_s: float = 15.0) -> None:
    deadline = time.perf_counter() + timeout_s
    while time.perf_counter() < deadline:
        if proc is not None and proc.poll() is not None:
            err = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
            raise RuntimeError(f"Server {name} exited early ({proc.returncode}): {err}")
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"Server {name} did not open {host}:{port} within {timeout_s}s")


def _recv_http_response(sock: socket.socket, buf: bytearray) -> tuple[int, bool]:
    while True:
        idx = buf.find(b"\r\n\r\n")
        if idx != -1:
            break
        chunk = sock.recv(8192)
        if not chunk:
            raise EOFError("EOF before HTTP headers")
        buf.extend(chunk)
    head = bytes(buf[:idx]).decode("latin1")
    lines = head.split("\r\n")
    status = int(lines[0].split()[1])
    cl = 0
    should_close = False
    for ln in lines[1:]:
        low = ln.lower()
        if low.startswith("content-length:"):
            cl = int(ln.split(":", 1)[1].strip())
        elif low.startswith("connection:") and "close" in low:
            should_close = True
    need = idx + 4 + cl
    while len(buf) < need:
        chunk = sock.recv(8192)
        if not chunk:
            raise EOFError("EOF before HTTP body")
        buf.extend(chunk)
    del buf[:need]
    return status, should_close


def _bench_raw_http(label: str, host: str, port: int, requests: list[bytes], threads: int = 4):
    per_thread = len(requests) // threads
    all_lats: list[list[int]] = [[] for _ in range(threads)]
    ok_cnt = [0] * threads
    blk_cnt = [0] * threads

    def _connect() -> socket.socket:
        s = socket.create_connection((host, port), timeout=10.0)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return s

    def worker(tid: int):
        batch = requests[tid * per_thread : (tid + 1) * per_thread]
        sock = _connect()
        buf = bytearray()
        for req in batch[:10]:
            try:
                sock.sendall(req)
                _, sc = _recv_http_response(sock, buf)
                if sc:
                    sock.close()
                    sock = _connect()
                    buf.clear()
            except OSError:
                sock.close()
                sock = _connect()
                buf.clear()

        lats = []
        ok = 0
        blk = 0
        for req in batch:
            t0 = time.perf_counter_ns()
            try:
                sock.sendall(req)
                st, sc = _recv_http_response(sock, buf)
                lats.append(time.perf_counter_ns() - t0)
                if st == 200:
                    ok += 1
                elif st in (400, 403, 429):
                    blk += 1
                if sc:
                    sock.close()
                    sock = _connect()
                    buf.clear()
            except (OSError, EOFError):
                lats.append(time.perf_counter_ns() - t0)
                blk += 1
                try:
                    sock.close()
                except OSError:
                    pass
                sock = _connect()
                buf.clear()
        sock.close()
        all_lats[tid] = lats
        ok_cnt[tid] = ok
        blk_cnt[tid] = blk

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(threads)]
    t_start = time.perf_counter_ns()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    total_ns = time.perf_counter_ns() - t_start

    merged = []
    for l in all_lats:
        merged.extend(l)
    merged.sort()
    n = len(merged)
    rps = (n * 1_000_000_000) / max(1, total_ns)
    p50 = merged[int(n * 0.50)] / 1000.0
    p99 = merged[int(n * 0.99)] / 1000.0
    mean = statistics.fmean(merged) / 1000.0
    print(
        f"  {label:<34} | {rps:>8,.0f} req/s | mean {mean:>7.1f} us | p50 {p50:>6.1f} us | p99 {p99:>7.1f} us | ok={sum(ok_cnt)} blk={sum(blk_cnt)}"
    )


def _bench_prm1(label: str, host: str, port: int, targets: list[str], threads: int = 4):
    per_thread = len(targets) // threads
    all_lats: list[list[int]] = [[] for _ in range(threads)]
    ok_cnt = [0] * threads
    blk_cnt = [0] * threads

    def worker(tid: int):
        batch = targets[tid * per_thread : (tid + 1) * per_thread]
        with PrimostrataClient(host, port, use_zin=False) as cli:
            for tgt in batch[:10]:
                cli.get(tgt)
            lats = []
            ok = 0
            blk = 0
            for tgt in batch:
                t0 = time.perf_counter_ns()
                st, _, _ = cli.get(tgt)
                lats.append(time.perf_counter_ns() - t0)
                if st == 200:
                    ok += 1
                elif st in (403, 429):
                    blk += 1
        all_lats[tid] = lats
        ok_cnt[tid] = ok
        blk_cnt[tid] = blk

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(threads)]
    t_start = time.perf_counter_ns()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    total_ns = time.perf_counter_ns() - t_start

    merged = []
    for l in all_lats:
        merged.extend(l)
    merged.sort()
    n = len(merged)
    rps = (n * 1_000_000_000) / max(1, total_ns)
    p50 = merged[int(n * 0.50)] / 1000.0
    p99 = merged[int(n * 0.99)] / 1000.0
    mean = statistics.fmean(merged) / 1000.0
    print(
        f"  {label:<34} | {rps:>8,.0f} req/s | mean {mean:>7.1f} us | p50 {p50:>6.1f} us | p99 {p99:>7.1f} us | ok={sum(ok_cnt)} blk={sum(blk_cnt)}"
    )


def _mk_http(target: str) -> bytes:
    return (
        f"GET {target} HTTP/1.1\r\n"
        f"Host: edge.primostrata.org\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode("ascii")


def main():
    sdk_root = os.path.dirname(os.path.abspath(__file__))
    with tempfile.TemporaryDirectory() as tmpdir:
        app_path = os.path.join(tmpdir, "top_apps.py")
        with open(app_path, "w", encoding="utf-8") as f:
            f.write(APPS_CODE)
        robyn_path = os.path.join(tmpdir, "robyn_srv.py")
        with open(robyn_path, "w", encoding="utf-8") as f:
            f.write(ROBYN_CODE)

        env = os.environ.copy()
        env["PYTHONPATH"] = f"{sdk_root}{os.pathsep}{tmpdir}"

        p_fa = _free_port()
        p_bsb = _free_port()
        p_bsw = _free_port()
        p_rob = _free_port()

        named_procs = [
            (
                "uvicorn-fastapi",
                p_fa,
                subprocess.Popen(
                    [sys.executable, "-m", "uvicorn", "top_apps:fastapi_bare", "--host", "127.0.0.1", "--port", str(p_fa), "--log-level", "critical", "--no-access-log"],
                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                ),
            ),
            (
                "granian-blacksheep-bare",
                p_bsb,
                subprocess.Popen(
                    [sys.executable, "-m", "granian", "top_apps:bs_bare", "--host", "127.0.0.1", "--port", str(p_bsb), "--interface", "asgi", "--http", "1", "--runtime-threads", "4", "--log-level", "critical", "--no-access-log"],
                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                ),
            ),
            (
                "granian-blacksheep-waf",
                p_bsw,
                subprocess.Popen(
                    [sys.executable, "-m", "granian", "top_apps:bs_waf", "--host", "127.0.0.1", "--port", str(p_bsw), "--interface", "asgi", "--http", "1", "--runtime-threads", "4", "--log-level", "critical", "--no-access-log"],
                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                ),
            ),
            (
                "robyn",
                p_rob,
                subprocess.Popen(
                    [sys.executable, robyn_path, str(p_rob)],
                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                ),
            ),
        ]
        procs = [p for _, _, p in named_procs]

        primo_app = PrimostrataApp(workers=4, edge_gate_secret=b"\x33" * 32)
        primo_app.static("/health", {"status": "ok", "engine": "primostrata"})

        @primo_app.get("/users/{uid}")
        async def get_user(uid: str):
            return {"uid": uid, "role": "merchant"}

        try:
            for name, port, proc in named_procs:
                _wait_port("127.0.0.1", port, proc=proc, name=name)

            with primo_app.running("127.0.0.1", 0):
                n_a = 12_000
                targets_a, reqs_a = [], []
                for i in range(n_a):
                    if i % 10 < 7:
                        t = "/health"
                    elif i % 3 == 0:
                        t = "/users/42?q=1+union%20select+password"
                    elif i % 3 == 1:
                        t = "/users/42?q=%3Cscript%3Ealert(1)%3C/script%3E"
                    else:
                        t = "/users/%2e%2e/admin"
                    targets_a.append(t)
                    reqs_a.append(_mk_http(t))

                print(f"\n=== Scenario A: Static/Const + L7 Attacks over TCP Keep-Alive ({n_a:,} req, 4 threads) ===")
                _bench_raw_http("Uvicorn + FastAPI (NO WAF)", "127.0.0.1", p_fa, reqs_a)
                _bench_raw_http("Granian + BlackSheep (NO WAF)", "127.0.0.1", p_bsb, reqs_a)
                _bench_raw_http("Granian + BlackSheep + PurePy WAF", "127.0.0.1", p_bsw, reqs_a)
                _bench_raw_http("Robyn const=True (NO WAF)", "127.0.0.1", p_rob, reqs_a)
                _bench_raw_http("PrimostrataApp HTTP/1.1 (+SHIELD)", "127.0.0.1", primo_app.port, reqs_a)
                _bench_prm1("PrimostrataApp PRM1 (+SHIELD)", "127.0.0.1", primo_app.port, targets_a)

                n_b = 8_000
                targets_b = [f"/users/{i % 1000}" for i in range(n_b)]
                reqs_b = [_mk_http(t) for t in targets_b]

                print(f"\n=== Scenario B: Async Dynamic Parameterized Route /users/{{uid}} ({n_b:,} req, 4 threads) ===")
                _bench_raw_http("Uvicorn + FastAPI (NO WAF)", "127.0.0.1", p_fa, reqs_b)
                _bench_raw_http("Granian(t=4)+BlackSheep (NO WAF)", "127.0.0.1", p_bsb, reqs_b)
                _bench_raw_http("Granian(t=4)+BlackSheep + WAF", "127.0.0.1", p_bsw, reqs_b)
                _bench_raw_http("Robyn dynamic (NO WAF)", "127.0.0.1", p_rob, reqs_b)
                _bench_raw_http("PrimostrataApp Async HTTP (REG)", "127.0.0.1", primo_app.port, reqs_b)
                _bench_prm1("PrimostrataApp Async PRM1 (REG)", "127.0.0.1", primo_app.port, targets_b)

                n_c = 12_800
                targets_c = [f"/users/{i % 1000}" for i in range(n_c)]
                reqs_c = [_mk_http(t) for t in targets_c]
                print(f"\n=== Scenario C: High Concurrency C=32 Async /users/{{uid}} ({n_c:,} req, 32 keep-alive conns on 4 REG cores) ===")
                _bench_raw_http("Uvicorn + FastAPI (NO WAF)", "127.0.0.1", p_fa, reqs_c, threads=32)
                _bench_raw_http("Granian(t=4)+BlackSheep (NO WAF)", "127.0.0.1", p_bsb, reqs_c, threads=32)
                _bench_raw_http("Granian(t=4)+BlackSheep + WAF", "127.0.0.1", p_bsw, reqs_c, threads=32)
                _bench_raw_http("Robyn dynamic (NO WAF)", "127.0.0.1", p_rob, reqs_c, threads=32)
                _bench_raw_http("PrimostrataApp Async HTTP (REG)", "127.0.0.1", primo_app.port, reqs_c, threads=32)
        finally:
            for p in procs:
                p.terminate()
            for p in procs:
                try:
                    p.wait(timeout=5)
                except Exception:
                    p.kill()


if __name__ == "__main__":
    main()
