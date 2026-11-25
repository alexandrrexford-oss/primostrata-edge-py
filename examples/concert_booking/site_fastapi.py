from __future__ import annotations

import os
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pure_python_edge import PurePythonEdge

from examples.concert_booking.db import audit_db, create_order, get_concert, get_order, list_concerts
from examples.concert_booking.templates import render_concert_detail_html, render_storefront_html

DB_PATH = os.environ.get("CONCERT_DB_PATH", "concert_fastapi.db")
STOREFRONT_BARE = render_storefront_html("FastAPI + Uvicorn")
STOREFRONT_WAF = render_storefront_html("FastAPI + Uvicorn + PurePy WAF")


def _build_fastapi(with_waf: bool) -> FastAPI:
    app = FastAPI(title="LivePass Concerts (FastAPI)")
    edge = PurePythonEdge() if with_waf else None
    storefront = STOREFRONT_WAF if with_waf else STOREFRONT_BARE
    lbl = "FastAPI + Uvicorn + PurePy WAF" if with_waf else "FastAPI + Uvicorn"

    if edge is not None:
        @app.middleware("http")
        async def pure_waf_middleware(request: Request, call_next):
            raw_target = request.url.path + (("?" + request.url.query) if request.url.query else "")
            url = f"https://edge.primostrata.org{raw_target}"
            hdrs = list(request.headers.items())
            if not edge.inspect(url, hdrs):
                return JSONResponse({"detail": "Blocked by PurePython WAF"}, status_code=403)
            return await call_next(request)

    @app.get("/")
    def home():
        return HTMLResponse(storefront)

    @app.get("/health")
    def health():
        return {"status": "ok", "stack": lbl}

    @app.get("/concerts/{cid}")
    def concert_page(cid: int):
        c = get_concert(DB_PATH, cid)
        if not c:
            return JSONResponse({"detail": "Concert not found"}, status_code=404)
        html = render_concert_detail_html(c, lbl)
        if edge is not None:
            clean = edge.strip_scripts(html.encode("utf-8"))
            return HTMLResponse(clean)
        return HTMLResponse(html)

    @app.get("/api/concerts")
    def api_concerts():
        return {"concerts": list_concerts(DB_PATH)}

    @app.post("/api/orders")
    def api_create_order(payload: dict):
        cid = int(payload.get("concert_id", 0))
        buyer = str(payload.get("buyer_name", "Guest"))
        qty = int(payload.get("qty", 1))
        st, out = create_order(DB_PATH, cid, buyer, qty)
        return JSONResponse(out, status_code=st)

    @app.get("/api/orders/{oid}")
    def api_get_order(oid: int):
        o = get_order(DB_PATH, oid)
        return JSONResponse(o, status_code=200) if o else JSONResponse({"detail": "Order not found"}, status_code=404)

    @app.get("/api/audit")
    def api_audit():
        return audit_db(DB_PATH)

    return app


app_bare = _build_fastapi(with_waf=False)
app_waf = _build_fastapi(with_waf=True)
