from __future__ import annotations

import glob
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

SERVER_DEFS = """
import sys
from fastapi import FastAPI
from blacksheep import Application, Content, Response
from blacksheep import json as bs_json
from blacksheep.server.routing import Router
from pure_python_edge import PurePythonEdge
from primostrata_edge import PrimostrataApp

# --- 1. FastAPI ---
fastapi_app = FastAPI()

@fastapi_app.get("/health")
async def fa_health():
    return {"status": "ok", "engine": "fastapi"}

@fastapi_app.get("/users/{uid}")
async def fa_user(uid: str):
    return {"uid": uid, "role": "merchant"}

# --- 2. BlackSheep (Bare & +WAF) ---
bs_bare = Application(router=Router())

@bs_bare.router.get("/health")
async def bsb_health():
    return bs_json({"status": "ok", "engine": "blacksheep"})

@bs_bare.router.get("/users/{uid}")
async def bsb_user(uid: str):
    return bs_json({"uid": uid, "role": "merchant"})

bs_waf = Application(router=Router())
_edge = PurePythonEdge()

async def _waf_mw(request, handler):
    url = f"https://edge.primostrata.org{request.url.value.decode('latin1')}"
    hdrs = [(k.decode('latin1'), v.decode('latin1')) for k, v in request.headers]
    if not _edge.inspect(url, hdrs):
        return Response(403, content=Content(b"application/json", b'{"detail":"Blocked"}'))
    return await handler(request)

bs_waf.middlewares.append(_waf_mw)

@bs_waf.router.get("/health")
async def bsw_health():
    return bs_json({"status": "ok", "engine": "blacksheep+waf"})

@bs_waf.router.get("/users/{uid}")
async def bsw_user(uid: str):
    return bs_json({"uid": uid, "role": "merchant"})
"""

ROBYN_SCRIPT = """
import os
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
    app.start(host="127.0.0.1", port=int(os.environ["SRV_PORT"]), _check_port=False)
"""

PRIMO_SCRIPT = """
import os
from primostrata_edge import PrimostrataApp

app = PrimostrataApp(workers=4, edge_gate_secret=b"\\x33" * 32)
app.static("/health", {"status": "ok", "engine": "primostrata"})

@app.get("/users/{uid}")
async def get_user(uid: str):
    return {"uid": uid, "role": "merchant"}

if __name__ == "__main__":
    app.serve(host="127.0.0.1", port=int(os.environ["SRV_PORT"]))
"""

K6_SCRIPT = """
import http from 'k6/http';
import { check } from 'k6';

const BASE = __ENV.BASE_URL;
const EXPECT_WAF = __ENV.EXPECT_WAF === '1';

export const options = {
  vus: 20,
  duration: '4s',
  summaryTrendStats: ['avg', 'med', 'p(90)', 'p(99)'],
};

export default function () {
  const iter = __ITER % 10;
  if (iter < 5) {
    const r = http.get(`${BASE}/health`);
    check(r, { 'health 200': (res) => res.status === 200 });
  } else if (iter < 7) {
    const r = http.get(`${BASE}/users/${__ITER % 1000}`);
    check(r, { 'dyn 200': (res) => res.status === 200 });
  } else {
    let url = `${BASE}/users/42?q=1+union%20select+password`;
    if (iter === 8) url = `${BASE}/users/42?q=%3Cscript%3Ealert(1)%3C/script%3E`;
    if (iter === 9) url = `${BASE}/users/%2e%2e/admin`;
    const r = http.get(url);
    if (EXPECT_WAF) {
      check(r, { 'attack 403': (res) => res.status === 403 });
    } else {
      check(r, { 'no-waf responded': (res) => res.status > 0 });
    }
  }
}
"""


def _find_exe(name: str, extra_globs: list[str]) -> str:
    found = shutil.which(name)
    if found:
        return found
    for pat in extra_globs:
        matches = glob.glob(os.path.expandvars(pat), recursive=True)
        if matches:
            return matches[0]
    raise FileNotFoundError(f"Executable not found: {name}")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_port(host: str, port: int, proc: subprocess.Popen, name: str, timeout_s: float = 15.0) -> None:
    deadline = time.perf_counter() + timeout_s
    while time.perf_counter() < deadline:
        if proc.poll() is not None:
            err = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
            raise RuntimeError(f"Server {name} exited ({proc.returncode}): {err}")
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"Server {name} timed out waiting on {host}:{port}")


def _run_oha(oha_exe: str, label: str, url: str, concurrency: int = 32, dur: str = "3s") -> None:
    cmd = [
        oha_exe,
        "--no-tui",
        "--output-format",
        "json",
        "-z",
        dur,
        "-c",
        str(concurrency),
        url,
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    data = json.loads(res.stdout)
    summary = data["summary"]
    rps = summary["requestsPerSec"]
    avg_ms = summary["average"] * 1000.0
    lat_pct = data.get("latencyPercentiles", {})
    p50_ms = lat_pct.get("p50", 0.0) * 1000.0
    p90_ms = lat_pct.get("p90", 0.0) * 1000.0
    p99_ms = lat_pct.get("p99", 0.0) * 1000.0
    ok_n = data.get("statusCodeDistribution", {}).get("200", 0)
    print(
        f"  {label:<34} | {rps:>9,.1f} req/s | avg {avg_ms:>6.2f} ms | p50 {p50_ms:>6.2f} ms | p90 {p90_ms:>6.2f} ms | p99 {p99_ms:>6.2f} ms | 200={ok_n}"
    )


def _run_k6(k6_exe: str, k6_path: str, label: str, base_url: str, expect_waf: bool, tmpdir: str, idx: int) -> None:
    summary_file = os.path.join(tmpdir, f"k6_{idx}.json")
    env = os.environ.copy()
    env["BASE_URL"] = base_url
    env["EXPECT_WAF"] = "1" if expect_waf else "0"
    subprocess.run(
        [k6_exe, "run", "--quiet", f"--summary-export={summary_file}", k6_path],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=True,
    )
    with open(summary_file, "r", encoding="utf-8") as f:
        rep = json.load(f)
    m = rep["metrics"]
    rps = m["http_reqs"]["rate"]
    total = m["http_reqs"]["count"]
    dur = m["http_req_duration"]
    checks = m.get("checks", {})
    chk_ok = checks.get("passes", 0)
    chk_fail = checks.get("fails", 0)
    print(
        f"  {label:<34} | {rps:>9,.1f} req/s | avg {dur['avg']:>6.2f} ms | p50 {dur['med']:>6.2f} ms | p90 {dur['p(90)']:>6.2f} ms | p99 {dur['p(99)']:>6.2f} ms | tot={total} chk={chk_ok}/{chk_ok + chk_fail}"
    )


def main():
    oha_exe = _find_exe(
        "oha",
        [r"%LOCALAPPDATA%\Microsoft\WinGet\Packages\hatoo.oha*\**\oha.exe"],
    )
    k6_exe = _find_exe(
        "k6",
        [r"C:\Program Files\k6\k6.exe", r"%LOCALAPPDATA%\Programs\k6\k6.exe"],
    )
    print(f"Tools: oha={oha_exe}\n       k6 ={k6_exe}")

    sdk_root = os.path.dirname(os.path.abspath(__file__))
    with tempfile.TemporaryDirectory() as tmpdir:
        srv_py = os.path.join(tmpdir, "srv_defs.py")
        robyn_py = os.path.join(tmpdir, "robyn_srv.py")
        primo_py = os.path.join(tmpdir, "primo_srv.py")
        k6_js = os.path.join(tmpdir, "mix.js")
        with open(srv_py, "w", encoding="utf-8") as f:
            f.write(SERVER_DEFS)
        with open(robyn_py, "w", encoding="utf-8") as f:
            f.write(ROBYN_SCRIPT)
        with open(primo_py, "w", encoding="utf-8") as f:
            f.write(PRIMO_SCRIPT)
        with open(k6_js, "w", encoding="utf-8") as f:
            f.write(K6_SCRIPT)

        env = os.environ.copy()
        env["PYTHONPATH"] = f"{sdk_root}{os.pathsep}{tmpdir}"

        specs = [
            ("Uvicorn(w=4)+FastAPI (NO WAF)", _free_port(), False, [sys.executable, "-m", "uvicorn", "srv_defs:fastapi_app", "--host", "127.0.0.1", "--workers", "4", "--log-level", "critical", "--no-access-log"]),
            ("Granian(t=4)+BlackSheep (NO WAF)", _free_port(), False, [sys.executable, "-m", "granian", "srv_defs:bs_bare", "--host", "127.0.0.1", "--interface", "asgi", "--http", "1", "--runtime-threads", "4", "--log-level", "critical", "--no-access-log"]),
            ("Granian(t=4)+BlackSheep + WAF", _free_port(), True, [sys.executable, "-m", "granian", "srv_defs:bs_waf", "--host", "127.0.0.1", "--interface", "asgi", "--http", "1", "--runtime-threads", "4", "--log-level", "critical", "--no-access-log"]),
            ("Robyn(w=4, const+dyn, NO WAF)", _free_port(), False, [sys.executable, robyn_py, "--workers", "4", "--log-level", "WARNING"]),
            ("PrimostrataApp(w=4, REG+SHIELD)", _free_port(), True, [sys.executable, primo_py]),
        ]

        running = []
        try:
            for label, port, expect_waf, base_cmd in specs:
                p_env = env.copy()
                if "robyn_srv.py" in base_cmd[1] or "primo_srv.py" in base_cmd[1]:
                    p_env["SRV_PORT"] = str(port)
                    cmd = base_cmd
                else:
                    cmd = base_cmd + ["--port", str(port)]
                proc = subprocess.Popen(cmd, env=p_env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                running.append((label, port, expect_waf, proc))

            for label, port, _, proc in running:
                _wait_port("127.0.0.1", port, proc, label)

            print("\n=== [oha 1.17.0 (Rust)] Test 1: Static/Const /health (c=32 connections, 3s Keep-Alive) ===")
            for label, port, _, _ in running:
                _run_oha(oha_exe, label, f"http://127.0.0.1:{port}/health", concurrency=32, dur="3s")

            print("\n=== [oha 1.17.0 (Rust)] Test 2: Async Dynamic /users/{uid} (c=32 connections, 3s Keep-Alive) ===")
            for label, port, _, _ in running:
                _run_oha(oha_exe, label, f"http://127.0.0.1:{port}/users/42", concurrency=32, dur="3s")

            print("\n=== [k6 2.4.0 (Go)] Test 3: Mixed Edge Workload (70% Honest Static+Dyn / 30% L7 Attacks, 20 VUs, 4s) ===")
            for idx, (label, port, expect_waf, _) in enumerate(running):
                _run_k6(k6_exe, k6_js, label, f"http://127.0.0.1:{port}", expect_waf, tmpdir, idx)
        finally:
            for _, _, _, proc in running:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    proc.terminate()
            for _, _, _, proc in running:
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()


if __name__ == "__main__":
    main()
