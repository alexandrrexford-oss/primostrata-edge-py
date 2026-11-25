from __future__ import annotations

import os
from primostrata_edge import PrimostrataApp, PrimostrataRequest, PrimostrataResponse

from examples.concert_booking.db import audit_db, create_order, get_concert, get_order, list_concerts
from examples.concert_booking.templates import render_concert_detail_html, render_storefront_html

DB_PATH = os.environ.get("CONCERT_DB_PATH", "concert_primostrata.db")
LABEL = "PrimostrataApp (REG + SHIELD + ZIN)"
STOREFRONT_HTML = render_storefront_html(LABEL)

app = PrimostrataApp(title="LivePass Concerts (Primostrata)", workers=4)

# Interactive storefront HTML preserves trusted booking <script> (strip_scripts=False)
app.static("/", STOREFRONT_HTML, content_type="text/html; charset=utf-8", strip_scripts=False)
app.static("/health", {"status": "ok", "stack": LABEL})


@app.get("/concerts/{cid}", strip_scripts=True)
async def concert_page(cid: int):
    c = get_concert(DB_PATH, cid)
    if not c:
        return PrimostrataResponse({"detail": "Concert not found"}, status_code=404)
    # Rust strips any <script> from user review cleanly on return
    return render_concert_detail_html(c, LABEL)


@app.get("/api/concerts")
async def api_concerts():
    return {"concerts": list_concerts(DB_PATH)}


@app.post("/api/orders")
async def api_create_order(req: PrimostrataRequest):
    payload = req.json()
    cid = int(payload.get("concert_id", 0))
    buyer = str(payload.get("buyer_name", "Guest"))
    qty = int(payload.get("qty", 1))
    st, out = create_order(DB_PATH, cid, buyer, qty)
    return PrimostrataResponse(out, status_code=st)


@app.get("/api/orders/{oid}")
async def api_get_order(oid: int):
    o = get_order(DB_PATH, oid)
    if not o:
        return PrimostrataResponse({"detail": "Order not found"}, status_code=404)
    return o


@app.get("/api/audit")
async def api_audit():
    return audit_db(DB_PATH)


if __name__ == "__main__":
    port = int(os.environ.get("SRV_PORT", "8080"))
    app.serve(host="127.0.0.1", port=port)
