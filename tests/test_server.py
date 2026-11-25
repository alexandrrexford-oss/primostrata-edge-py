import asyncio
import concurrent.futures
import socket

import httpx
import pytest

from primostrata_edge import PrimostrataApp, PrimostrataClient, PrimostrataRequest


def test_primostrata_app_http_and_security():
    app = PrimostrataApp(workers=4)
    calls = {"dyn": 0, "cached": 0}

    app.static("/health", {"status": "ok", "engine": "primostrata"})

    @app.get("/users/{uid}")
    async def get_user(uid: int, page: int = 1):
        calls["dyn"] += 1
        return {"uid": uid, "page": page, "role": "merchant"}

    @app.get("/html-safe")
    def html_safe():
        return "<div>Hello<script>evil()</script></div>"

    @app.get("/cached", cacheable=True)
    async def cached_page():
        calls["cached"] += 1
        return {"hit_source": "origin", "seq": calls["cached"]}

    @app.post("/echo")
    async def echo(req: PrimostrataRequest):
        data = req.json()
        return {"received": data["msg"], "path": req.path}

    with app.running("127.0.0.1", 0) as base_url:
        with httpx.Client(base_url=base_url, timeout=3.0) as client:
            # 1. Static zero-GIL route & auto-generated OpenAPI/Docs
            r = client.get("/health")
            assert r.status_code == 200
            assert r.json() == {"status": "ok", "engine": "primostrata"}
            assert client.get("/openapi.json").json()["paths"]["/users/{uid}"]["get"]
            assert client.get("/docs").status_code == 200

            # 2. Async dynamic route with typed int path + query param + 422 check
            r = client.get("/users/42?page=3")
            assert r.status_code == 200
            assert r.json() == {"uid": 42, "page": 3, "role": "merchant"}
            assert calls["dyn"] == 1
            assert client.get("/users/not_an_int").status_code == 422

            # 3. HTML <script> stripping automatically in Rust
            r = client.get("/html-safe")
            assert r.status_code == 200
            assert r.text == "<div>Hello</div>"

            # 4. Per-core REG STORE64 Edge cache HIT (first hit per worker warms core, never misses same conn)
            c1 = client.get("/cached")
            c2 = client.get("/cached")
            assert c1.status_code == 200
            assert c1.json() == c2.json()
            assert c1.json()["seq"] >= 1
            before = calls["cached"]
            assert client.get("/cached").json() == c1.json()
            assert calls["cached"] == before

            # 5. POST JSON
            p = client.post("/echo", json={"msg": "primostrata"})
            assert p.status_code == 200
            assert p.json() == {"received": "primostrata", "path": "/echo"}

            # 6. SHIELD L4/L7 blocks attacks directly in Rust with 403
            for attack_url in (
                "/users/42?q=1+union%20select+password",
                "/users/42?q=%3Cscript%3Ealert(1)%3C/script%3E",
                "/users/%2e%2e/admin",
            ):
                blk = client.get(attack_url)
                assert blk.status_code == 403, f"Expected 403 for {attack_url}, got {blk.status_code}"

            with socket.create_connection(("127.0.0.1", app.port), timeout=2.0) as s:
                s.sendall(b"GET /static/../../etc/passwd HTTP/1.1\r\nHost: edge.primostrata.org\r\nConnection: close\r\n\r\n")
                assert s.recv(4096).startswith(b"HTTP/1.1 403 ")

            assert calls["dyn"] == 1

            # 7. Native PRM1 binary wire protocol on the SAME port
            with PrimostrataClient("127.0.0.1", app.port, use_zin=True) as bin_cli:
                st, ct, body = bin_cli.get("/health")
                assert st == 200 and ct == "application/json"
                assert b'"engine":"primostrata"' in body

                st2, _, body2 = bin_cli.get("/users/99")
                assert st2 == 200 and b'"uid":99' in body2

                st_blk, _, _ = bin_cli.get("/users/1?q=<script>x</script>")
                assert st_blk == 403


def test_primostrata_app_async_await_and_high_concurrency():
    app = PrimostrataApp(workers=4, edge_gate_secret=b"\x33" * 32)
    app.static("/fast", {"fast": True})

    @app.get("/io/{item_id}")
    async def async_io(item_id: int):
        await asyncio.sleep(0.015)
        return {"id": item_id, "awaited": True}

    with app.running("127.0.0.1", 0) as base_url:
        # 24 simultaneous concurrent clients (> 4 worker threads!) proving non-blocking REG reactor + asyncio
        def hit_once(i: int):
            with httpx.Client(base_url=base_url, timeout=5.0) as c:
                r1 = c.get("/fast")
                r2 = c.get(f"/io/{i}")
                # Invalid PoW rejected by EdgeGateState
                r_bad = c.get("/fast", headers={"X-Primo-PoW": "1234:deadbeef"})
                return r1.status_code, r2.json(), r_bad.status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
            results = list(pool.map(hit_once, range(24)))

        for idx, (s1, js, s_bad) in enumerate(results):
            assert s1 == 200
            assert js == {"id": idx, "awaited": True}
            assert s_bad == 403


def test_primostrata_app_rate_limit():
    app = PrimostrataApp(rate_limit_per_sec=3, workers=2)
    app.static("/ping", "pong")

    with app.running("127.0.0.1", 0) as base_url:
        with httpx.Client(base_url=base_url, timeout=3.0) as client:
            statuses = [client.get("/ping").status_code for _ in range(5)]
            assert statuses[:3] == [200, 200, 200]
            assert 429 in statuses[3:]
