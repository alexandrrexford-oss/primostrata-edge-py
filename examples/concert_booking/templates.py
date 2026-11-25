from __future__ import annotations

from html import escape
from typing import Any, Dict


def render_storefront_html(stack_label: str) -> str:
    lbl = escape(stack_label)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>LivePass Concerts — {lbl}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #e6edf3; margin: 0; padding: 32px; }}
    .wrap {{ max-width: 920px; margin: 0 auto; }}
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 999px; background: #1f6feb33; color: #58a6ff; font-size: 13px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-top: 20px; }}
    .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 18px; }}
    button {{ background: #238636; color: #fff; border: 0; border-radius: 8px; padding: 8px 14px; cursor: pointer; font-weight: 600; }}
    input {{ background: #0d1117; color: #e6edf3; border: 1px solid #30363d; border-radius: 8px; padding: 7px 10px; width: 100%; box-sizing: border-box; margin-bottom: 8px; }}
    #receipt {{ margin-top: 20px; padding: 14px; border-radius: 8px; background: #161b22; border: 1px solid #30363d; display: none; }}
  </style>
</head>
<body>
  <div class="wrap">
    <span class="badge">Engine: {lbl}</span>
    <h1>LivePass Concert Tickets</h1>
    <p>Real SQLite WAL inventory, instant atomic booking, and L4/L7 edge protection.</p>
    <div id="concerts" class="grid">Loading concerts...</div>
    <div id="receipt"></div>
  </div>
  <script>
    async function loadConcerts() {{
      const res = await fetch('/api/concerts');
      const data = await res.json();
      const box = document.getElementById('concerts');
      box.innerHTML = data.concerts.map(c => `
        <div class="card">
          <h3><a href="/concerts/${{c.id}}" style="color:#58a6ff">${{c.title}}</a></h3>
          <div>${{c.venue}} &middot; ${{c.event_date}}</div>
          <p><strong>$${{c.price}}</strong> &middot; Left: <b>${{c.remaining_seats}}</b></p>
          <input id="buyer-${{c.id}}" placeholder="Your name" value="Alex" />
          <button onclick="book(${{c.id}})">Buy 1 Ticket</button>
        </div>
      `).join('');
    }}
    async function book(cid) {{
      const name = document.getElementById('buyer-' + cid).value || 'Guest';
      const r = await fetch('/api/orders', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ concert_id: cid, buyer_name: name, qty: 1 }})
      }});
      const out = await r.json();
      const rec = document.getElementById('receipt');
      rec.style.display = 'block';
      rec.textContent = JSON.stringify(out);
      loadConcerts();
    }}
    loadConcerts();
  </script>
</body>
</html>"""


def render_concert_detail_html(concert: Dict[str, Any], stack_label: str) -> str:
    # Intentionally embeds concert["featured_review"] directly so server HTML script-stripping is exercised!
    return (
        f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>{escape(concert['title'])}</title></head>"
        f"<body><span class='engine'>{escape(stack_label)}</span>"
        f"<h1>{escape(concert['title'])}</h1>"
        f"<p>{escape(concert['venue'])} | {escape(concert['event_date'])} | Price: ${concert['price']}</p>"
        f"<p>Remaining seats: {concert['remaining_seats']}</p>"
        f"<section class='review'>Featured fan review: {concert['featured_review']}</section>"
        f"</body></html>"
    )
