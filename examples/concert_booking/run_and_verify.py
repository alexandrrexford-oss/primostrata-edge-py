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

import httpx

from examples.concert_booking.db import init_db

K6_WEBSITE_JS = """
import http from 'k6/http';
import { check } from 'k6';

const BASE = __ENV.BASE_URL;
const EXPECT_WAF = __ENV.EXPECT_WAF === '1';
const JSON_HDR = { headers: { 'Content-Type': 'application/json' } };

export const options = {
  vus: 20,
  duration: '4s',
  summaryTrendStats: ['avg', 'med', 'p(90)', 'p(99)'],
};

export default function () {
  const m = __ITER % 20;
  if (m < 7) {
    // 35% Full HTML Storefront
    const r = http.get(`${BASE}/`);
    check(r, { 'home 200': (res) => res.status === 200 });
  } else if (m < 12) {
    // 25% Real SQLite catalog read
    const r = http.get(`${BASE}/api/concerts`);
    check(r, { 'catalog 200': (res) => res.status === 200 });
  } else if (m < 15) {
    // 15% SSR concert page with SQLite lookup + XSS strip
    const cid = (__ITER % 3) + 1;
    const r = http.get(`${BASE}/concerts/${cid}`);
    check(r, { 'detail 200': (res) => res.status === 200 });
  } else if (m < 17) {
    // 10% Real SQLite BEGIN IMMEDIATE order write
    const cid = (__ITER % 3) + 1;
    const r = http.post(`${BASE}/api/orders`, `{"concert_id":${cid},"buyer_name":"User${__VU}","qty":1}`, JSON_HDR);
    check(r, { 'order 201': (res) => res.status === 201 });
  } else {
    // 15% Scalper L7 attacks
    let url = `${BASE}/concerts/1?q=1+union%20select+password`;
    if (m === 18) url = `${BASE}/concerts/1?q=%3Cscript%3Ealert(1)%3C/script%3E`;
    if (m === 19) url = `${BASE}/concerts/%2e%2e/admin`;
    const r = http.get(url);
    if (EXPECT_WAF) {
      check(r, { 'attack 403': (res) => res.status === 403 });
    } else {
      check(r, { 'no-waf resp': (res) => res.status > 0 });
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
            raise RuntimeError(f"Website {name} exited ({proc.returncode}): {err}")
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"Website {name} did not open {host}:{port}")


def verify_e2e_website(label: str, base_url: str, expect_waf: bool) -> None:
    with httpx.Client(base_url=base_url, timeout=5.0) as c:
        # 1. Interactive Storefront HTML
        r_home = c.get("/")
        assert r_home.status_code == 200
        assert "LivePass Concert Tickets" in r_home.text
        assert "loadConcerts()" in r_home.text

        # 2. SSR Detail Page + XSS review sanitization
        r_det = c.get("/concerts/1")
        assert r_det.status_code == 200
        assert "Synthwave Arena Tour" in r_det.text
        if expect_waf:
            assert "<script" not in r_det.text.lower(), f"{label} leaked <script> XSS in detail page!"

        # 3. SQLite Catalog API
        r_cat = c.get("/api/concerts")
        assert r_cat.status_code == 200
        concerts = r_cat.json()["concerts"]
        assert len(concerts) == 3
        before_rem = concerts[0]["remaining_seats"]

        # 4. Real SQLite Atomic Booking + Order Persistence
        r_ord = c.post("/api/orders", json={"concert_id": 1, "buyer_name": "Iskander", "qty": 2})
        assert r_ord.status_code == 201
        ord_data = r_ord.json()
        assert ord_data["remaining_seats"] == before_rem - 2
        assert ord_data["total_price"] == 240

        r_get_ord = c.get(f"/api/orders/{ord_data['order_id']}")
        assert r_get_ord.status_code == 200
        assert r_get_ord.json()["buyer_name"] == "Iskander"
        assert r_get_ord.json()["qty"] == 2

        # 5. Validation errors
        assert c.post("/api/orders", json={"concert_id": 1, "qty": 99}).status_code == 400
        assert c.post("/api/orders", json={"concert_id": 999, "qty": 1}).status_code == 404

        # 6. WAF L7 protection
        if expect_waf:
            for atk in (
                "/concerts/1?q=1+union%20select+password",
                "/concerts/1?q=%3Cscript%3Ealert(1)%3C/script%3E",
                "/concerts/%2e%2e/admin",
            ):
                blk = c.get(atk)
                assert blk.status_code == 403, f"{label} failed to block {atk} (got {blk.status_code})"

    print(f"  [E2E PASS] {label}")


def _run_oha(oha_exe: str, label: str, url: str, concurrency: int, method: str = "GET", body: str | None = None, dur: str = "3s") -> None:
    cmd = [oha_exe, "--no-tui", "--output-format", "json", "-z", dur, "-c", str(concurrency)]
    if method == "POST":
        cmd += ["-m", "POST", "-T", "application/json", "-d", body or "{}"]
    cmd.append(url)
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    data = json.loads(res.stdout)
    s = data["summary"]
    pct = data.get("latencyPercentiles", {})
    dist = data.get("statusCodeDistribution", {})
    ok_cnt = dist.get("200", 0) + dist.get("201", 0)
    print(
        f"  {label:<34} | {s['requestsPerSec']:>8,.1f} req/s | avg {s['average']*1000:>5.2f} ms | p50 {pct.get('p50',0)*1000:>5.2f} ms | p99 {pct.get('p99',0)*1000:>5.2f} ms | ok={ok_cnt}"
    )


def _run_k6(k6_exe: str, k6_js: str, label: str, base_url: str, expect_waf: bool, tmpdir: str, idx: int) -> None:
    out_json = os.path.join(tmpdir, f"k6_site_{idx}.json")
    env = os.environ.copy()
    env["BASE_URL"] = base_url
    env["EXPECT_WAF"] = "1" if expect_waf else "0"
    subprocess.run(
        [k6_exe, "run", "--quiet", f"--summary-export={out_json}", k6_js],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True,
    )
    with open(out_json, "r", encoding="utf-8") as f:
        rep = json.load(f)
    m = rep["metrics"]
    dur = m["http_req_duration"]
    chk = m.get("checks", {})
    audit = httpx.get(f"{base_url}/api/audit", timeout=5.0).json()
    print(
        f"  {label:<34} | {m['http_reqs']['rate']:>8,.1f} req/s | avg {dur['avg']:>5.2f} ms | p90 {dur['p(90)']:>5.2f} ms | p99 {dur['p(99)']:>5.2f} ms | chk={chk.get('passes',0)}/{chk.get('passes',0)+chk.get('fails',0)} | sold={audit['sold_tickets']} inv_ok={audit['invariant_ok']}"
    )


def main():
    oha_exe = _find_exe("oha", [r"%LOCALAPPDATA%\Microsoft\WinGet\Packages\hatoo.oha*\**\oha.exe"])
    k6_exe = _find_exe("k6", [r"C:\Program Files\k6\k6.exe", r"%LOCALAPPDATA%\Programs\k6\k6.exe"])
    sdk_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    with tempfile.TemporaryDirectory() as tmpdir:
        db_bare = os.path.join(tmpdir, "fa_bare.db")
        db_waf = os.path.join(tmpdir, "fa_waf.db")
        db_primo = os.path.join(tmpdir, "primo.db")
        for dbp in (db_bare, db_waf, db_primo):
            init_db(dbp)

        k6_js = os.path.join(tmpdir, "website_mix.js")
        with open(k6_js, "w", encoding="utf-8") as f:
            f.write(K6_WEBSITE_JS)

        specs = [
            (
                "FastAPI + Uvicorn (w=4, NO WAF)",
                _free_port(),
                db_bare,
                False,
                [sys.executable, "-m", "uvicorn", "examples.concert_booking.site_fastapi:app_bare", "--host", "127.0.0.1", "--workers", "4", "--log-level", "critical", "--no-access-log"],
                True,
            ),
            (
                "FastAPI + Uvicorn (w=4, +PurePy WAF)",
                _free_port(),
                db_waf,
                True,
                [sys.executable, "-m", "uvicorn", "examples.concert_booking.site_fastapi:app_waf", "--host", "127.0.0.1", "--workers", "4", "--log-level", "critical", "--no-access-log"],
                True,
            ),
            (
                "PrimostrataApp (w=4, +SHIELD+ZIN)",
                _free_port(),
                db_primo,
                True,
                [sys.executable, "-m", "examples.concert_booking.site_primostrata"],
                False,
            ),
        ]

        running = []
        try:
            for label, port, dbp, expect_waf, base_cmd, is_uvi in specs:
                env = os.environ.copy()
                env["PYTHONPATH"] = sdk_root
                env["CONCERT_DB_PATH"] = dbp
                env["SRV_PORT"] = str(port)
                cmd = (base_cmd + ["--port", str(port)]) if is_uvi else base_cmd
                proc = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                running.append((label, port, expect_waf, proc))

            for label, port, _, proc in running:
                _wait_port("127.0.0.1", port, proc, label)

            print("\n=== 1. End-to-End Full-Stack Website Verification (HTML + SQLite WAL + Orders + XSS + WAF) ===")
            for label, port, expect_waf, _ in running:
                verify_e2e_website(label, f"http://127.0.0.1:{port}", expect_waf)

            print("\n=== 2. [oha 1.17.0] Website HTML Storefront GET / (c=32, 3s) ===")
            for label, port, _, _ in running:
                _run_oha(oha_exe, label, f"http://127.0.0.1:{port}/", concurrency=32)

            print("\n=== 3. [oha 1.17.0] SQLite WAL Catalog Read GET /api/concerts (c=32, 3s) ===")
            for label, port, _, _ in running:
                _run_oha(oha_exe, label, f"http://127.0.0.1:{port}/api/concerts", concurrency=32)

            print("\n=== 4. [oha 1.17.0] SQLite WAL Atomic Booking Write POST /api/orders (c=16, 3s) ===")
            for label, port, _, _ in running:
                _run_oha(oha_exe, label, f"http://127.0.0.1:{port}/api/orders", concurrency=16, method="POST", body='{"concert_id":2,"buyer_name":"Bench","qty":1}')

            print("\n=== 5. [k6 2.4.0] Realistic Website Mix (35% HTML + 25% DB Read + 15% SSR XSS-Strip + 10% DB Order + 15% L7 Bots, 20 VUs, 4s) ===")
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
